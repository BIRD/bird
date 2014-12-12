#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <loudmouth/loudmouth.h>

#include <pthread.h>
#include <unistd.h>
#include <getopt.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <fcntl.h>
#include <netdb.h>
#include <resolv.h>

#include "birdbot.h"
#include "sysdep/paths.h"

#define PIP_RD	0
#define PIP_WR 1

/****************************** SETTINGS ************************************/

#define PATH_CONFIG					PATH_BOT_CONFIG_FILE
#define PATH_LOCKFILE				"/var/run/birdbot.lock"
#define XMPP_KEEPALIVE_INTERVAL		120

/*****************************************************************************/

char*	superusers[100];
char*	restricted_users[100];

char*	birdbot_jid;
char*	birdbot_pw;
char bird_socket[108];

LmConnection	*xmpp_conn = NULL;
pthread_t		xmpp_keepalive_tid = -1;
int 			xmpp_keepalive_termpipe[2] = {-1, -1};
GMainLoop		*main_loop = NULL;

typedef struct {
	char* jid;
	struct {
		int is_muc;
		enum {
			XMPP_MUC_STATE_INIT = 0,
			XMPP_MUC_STATE_AWAITING_PRESENCES,
			XMPP_MUC_STATE_WORKING
		} muc_state;
	} muc;
	int bird_ready;
	int sock_fd;
	int termpipe_fd[2];
}conn_t;

typedef struct clitem {
	conn_t* connection;
	struct clitem* next;
}conn_listitem_t;

conn_listitem_t* conn_list = NULL;

pthread_mutex_t listmtx = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t xmppmtx = PTHREAD_MUTEX_INITIALIZER;

/**
 * Adds socket connection object to list
 * @param conn	Reference to object
 * @return		0 = OK, -1 = ERROR
 */
int list_add_end(conn_t* conn) {
	conn_listitem_t* c_tmp;

	pthread_mutex_lock(&listmtx);

	c_tmp = conn_list;

	if(conn_list == NULL) {
		conn_list = (conn_listitem_t*) malloc(sizeof(conn_listitem_t));
		if(conn_list == NULL) {
			pthread_mutex_unlock(&listmtx);
			return -1;
		}
		conn_list->connection = conn;
		conn_list->next = NULL;
	}
	else {
		while(c_tmp->next != NULL) {
			c_tmp = c_tmp->next;
		}
		c_tmp->next = (conn_listitem_t*) malloc(sizeof(conn_listitem_t));
		if(c_tmp->next == NULL) {
			pthread_mutex_unlock(&listmtx);
			return -1;
		}
		c_tmp->next->connection = conn;
		c_tmp->next->next = NULL;
	}

	pthread_mutex_unlock(&listmtx);
	return 0;
}

/**
 * Removes connection from list
 * @param jid	JabberID of user
 * @return		O = OK, -1 = ERROR
 */
int list_remove(char* jid) {
	conn_listitem_t* c_tmp;
	conn_listitem_t* c_tmp_prev = NULL;

	pthread_mutex_lock(&listmtx);

	if(conn_list == NULL) {
		pthread_mutex_unlock(&listmtx);
		return -1;
	}

	c_tmp = conn_list;

	while(c_tmp != NULL) {
		if(strcmp((c_tmp->connection)->jid, jid) == 0) {
			if(c_tmp_prev == NULL)	//prvni polozka seznamu
				conn_list = c_tmp->next;
			else
				c_tmp_prev->next = c_tmp->next;
			free(c_tmp);
			pthread_mutex_unlock(&listmtx);
			return 0;
		}
		c_tmp_prev = c_tmp;
		c_tmp = c_tmp->next;
	}

	pthread_mutex_unlock(&listmtx);
	return -1;
}

/**
 * Finds connection with specific JabberID in the list
 * @param jid	JabberID of user
 * @return		Odkaz na spojeni, NULL = ERROR
 */
conn_t* find_connection(char* jid) {
	conn_listitem_t* c_tmp = conn_list;

	pthread_mutex_lock(&listmtx);

	while(c_tmp != NULL) {
		if(strcmp((c_tmp->connection)->jid, jid) == 0) {
			pthread_mutex_unlock(&listmtx);
			return c_tmp->connection;
		}
		c_tmp = c_tmp->next;
	}

	pthread_mutex_unlock(&listmtx);
	return NULL;
}

/**
 * Prints entire list of connections, for debugging purposes
 */
void print_list(void) {
	conn_listitem_t* c_tmp = conn_list;
	while(c_tmp != NULL) {
		puts((c_tmp->connection)->jid);
		c_tmp = c_tmp->next;
	}
	puts("-----");
}

/**
 * Exits program with error message
 * @param s		Error message text
 */
void die(char* s) {
	puts(s);
	exit(-1);
}

/**
 * Skips leading whitespace characters in given string
 * @param str	String
 * @return		Pointer to first non-white character
 */
char* skipblank(char* str) {
	while((*str == ' ') || (*str == '\t'))
		str++;
	return str;
}

/**
 * Creates new connection with BIRD socket and adds it to the list
 * @param jid	JabberID of user
 * @return		0 = OK, -1 = ERROR
 */
int create_connection(char* jid, int is_muc) {
	struct sockaddr_un sa;
	conn_t* conn;

	/*if(is_muc && (muc_room_jid_bare == NULL))
		return -5;*/

	conn = (conn_t*) calloc(1, sizeof(conn_t));
	if(conn == NULL)
		return -1;

	conn->muc.is_muc = is_muc;

	if((conn->sock_fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
		free(conn);
		return -2;
	}

	memset(&sa, 0, sizeof(struct sockaddr_un));
	//inet_aton(BIRD_host, &(adr.sin_addr));
	sa.sun_family = AF_UNIX;
	strncpy(sa.sun_path, bird_socket, sizeof(sa.sun_path) - 1);
	sa.sun_path[sizeof(sa.sun_path) - 1] = '\0';
	//adr.sin_port = htons(BIRD_host_port);

	if(connect(conn->sock_fd, (struct sockaddr*) &sa, SUN_LEN(&sa)) < 0) {
		free(conn);
		return -3;
	}

	fcntl(conn->sock_fd, F_SETFL, O_NONBLOCK);

	conn->jid = strdup(jid);

	if(pipe(conn->termpipe_fd) != 0) {
		puts("Error creating pipe.");
		free(conn);
		return -4;
	}

	list_add_end(conn);

	return 0;
}

int close_connection(conn_t* conn) {
	close(conn->sock_fd);
	close(conn->termpipe_fd[PIP_RD]);
	close(conn->termpipe_fd[PIP_WR]);
	return 0;
}

int delete_connection(conn_t* conn) {

	if(list_remove(conn->jid) != 0)
		return -1;

	close_connection(conn);

	free(conn->jid);
	free(conn);

	return 0;
}

/**
 * Exits connection thread and removes it from the list
 * @param conn	Reference to connection object
 * @return		0 = OK, -1 = ERROR
 */
int connection_stop(conn_t* conn) {
	if(write(conn->termpipe_fd[PIP_WR], "stop", 5) == 5)
		return 0;
	else
		return -1;
}

/**
 * Clean exit of program, exits the all threads and does some housekeeping
 */
void exit_clean(int exitno) {
	conn_listitem_t* c_tmp = conn_list;
	char** ptr;
	int timeout = 20;


	while(c_tmp != NULL) {
		connection_stop(c_tmp->connection);
		c_tmp = c_tmp->next;
	}

	if(xmpp_conn != NULL) {
		lm_connection_close(xmpp_conn, NULL);
		lm_connection_unref(xmpp_conn);
	}

	if(main_loop != NULL) {
		g_main_loop_quit(main_loop);
		g_main_loop_unref(main_loop);
		g_main_loop_unref(main_loop);
	}

	free(birdbot_jid);
	free(birdbot_pw);

	ptr = superusers;
	while(*ptr != NULL) {
		free(*ptr);
		ptr++;
	}

	ptr = restricted_users;
	while(*ptr != NULL) {
		free(*ptr);
		ptr++;
	}

	//pockame na ukonceni vsech vlaken spojeni
	while((conn_list != NULL) && timeout) {
		usleep(100000);
		timeout--;
	}

	if(xmpp_keepalive_tid != -1) {
		timeout = 20;
		if(write(xmpp_keepalive_termpipe[PIP_WR], "stop", 5))
		{};
		while(!pthread_kill(xmpp_keepalive_tid, 0) && timeout) {
			usleep(100000);
			timeout--;
		}
	}

	puts("Program ended.");
	exit(exitno);
}

/**
 * Processes BIRD server response
 * @param in	Raw data string from BIRD socket
 * @return		Plain text (newly allocated), NULL = ERROR
 */
char* process_bird_output(char* in) {
	char* out = malloc(4096);
	char* line_end;
	int code;

	if(out == NULL)
		return NULL;

	out[0] = '\0';

	if(in[0] == '+') {
		//asynchronous server response
		sprintf(out, "\n>>> %s", in + 1);
		return out;
	}

	while((line_end = strchr(in, '\n')) != NULL) {
		*line_end = '\0';
		if((strlen(in) > 4) && (sscanf(in, "%04d", &code) == 1) && ((in[4] == ' ') || (in[4] == '-'))) {
			//valid line
			if(strlen(in) > 5) {
				strcat(out, "\n");
				strcat(out, in + 5);
			}
		}
		else if((strlen(in) > 2) && (in[0] == ' ')) {
			strcat(out, "\n");
			strcat(out, in + 1);
		}

		in = line_end + 1;
	}

	return out;
}

/**
 * Vlakno zajistujici cteni dat z BIRD socketu pro jednotlive uzivatele
 * @param args	Odkaz na objekt (conn_t*) spojeni
 */
void* connection_run_thread(void* args) {
	char tmp[4096];
	conn_t* conn = (conn_t*) args;
	fd_set fds;
	int maxfd;
	int timeout;

	maxfd = conn->sock_fd;
	if(conn->termpipe_fd[PIP_RD] > maxfd)
		maxfd = conn->termpipe_fd[PIP_RD];

	printf("Socket connection thread created: %s\n", conn->jid);
	while(1) {
		FD_ZERO(&fds);
		FD_SET(conn->sock_fd, &fds);
		FD_SET(conn->termpipe_fd[PIP_RD], &fds);

		select(maxfd + 1, &fds, NULL, NULL, NULL);

		if(FD_ISSET(conn->termpipe_fd[PIP_RD], &fds)) {
			break;
		}
		else if(FD_ISSET(conn->sock_fd, &fds)) {
			int bytes;
			char* msg;

			bytes = recv(conn->sock_fd, tmp, 4095, MSG_DONTWAIT);
			if(bytes <= 0)
				break;

			tmp[bytes] = '\0';
			printf("Received from socket: %d bytes: %s\n", bytes, tmp);

			msg = process_bird_output(tmp);


			if(!conn->bird_ready) {
				if(strstr(msg, "BIRD ") != NULL) {
					if(check_user_auth(conn->jid, conn->muc.is_muc) < 2) {
						if(write(conn->sock_fd, "restrict\n", 9) <= 0) {
							puts("Cannot write to socket, exiting thread.");
							free(msg);
							break;
						}
					}
					conn->bird_ready = 1;
				}
			}

			if(conn->muc.is_muc) {
				timeout = 500; //5 s
				while((conn->muc.muc_state != XMPP_MUC_STATE_WORKING) && timeout--)
					usleep(10000);
				if(timeout == 0) {
					PRINTF_XMPP_RED("MUC state != Working, exiting thread");
					free(msg);
					break;
				}
			}

			send_message(conn->jid, conn->muc.is_muc, msg);
			free(msg);
		}
	}


	printf("Connection thread %s ended.\n", conn->jid);

	if(delete_connection(conn) != 0)
		puts("Error deleting connection");

	return NULL;
}

/**
 * Executes specific BIRD socket connetion thread
 * @param conn	Connection object reference
 * @return		0 = OK, -1 = ERROR
 */
int connection_run(conn_t* conn) {
	pthread_t tid;
	pthread_create(&tid, NULL, connection_run_thread, conn);
	if(tid != 0)
		return -1;

	pthread_detach(tid);
	return 0;
}

/**
 * [API] Makes new connection and runs associated thread
 * @param jid		JabberID of connection object
 * @param is_muc	Is multi-user chat connection?
 * @return			0 = OK, -1 = ERROR
 */
int connection_new(char* jid, int is_muc) {
	conn_t* conn;
	int cc_exitno;

	if((cc_exitno = create_connection(jid, is_muc)) == 0) {
		conn = find_connection(jid);
		connection_run(conn);
		return 0;
	}
	else {
		printf("Error connecting room_jid BIRD socket (%s), exitno=%d.\n", bird_socket, cc_exitno);
		return -1;
	}
}

/**
 * Returns the Bare JID part of Full JID
 * @param jid	Full JID
 * @return		Bare JID (newly allocated)
 */
char* xmpp_trim_jid_by_slash(const char* jid) {
	char *ptr, *retval;

	if(jid == NULL)
		return NULL;

	retval = NULL;
	if((ptr = strchr(jid, '/')) != NULL) {
		retval = malloc(ptr - jid + 1);
		strncpy(retval, jid, ptr - jid);
		retval[ptr - jid] = '\0';
	}
	else {
		retval = strdup(jid);
	}
	return retval;
}

/**
 * Sends message over XMPP
 * @param jid		Chat:JabberID of recipient, MUC: bare room jid, full room jid with nickname (will be trimmed)
 * @param mbody		Message body text
 */
void send_message(char* jid, int is_muc, char* mbody) {
    LmMessage*	msg;
    char *jid_local;

    jid_local = NULL;
    //trim full MUC JID to bare MUC JID
    if(is_muc && strchr(jid, '/')) {
    	jid_local = alloca(strlen(jid));
    	strcpy(jid_local, jid);
    	*strchr(jid_local, '/') = '\0';
    }
    else
    	jid_local = jid;

    pthread_mutex_lock(&xmppmtx);

	msg = lm_message_new_with_sub_type(jid_local, LM_MESSAGE_TYPE_MESSAGE, is_muc?LM_MESSAGE_SUB_TYPE_GROUPCHAT:LM_MESSAGE_SUB_TYPE_CHAT);
	lm_message_node_add_child (msg->node, "body", mbody);
	//printf("XMPP: Sending message to %s (muc: %d)\n", jid_local, is_muc);
	lm_connection_send(xmpp_conn, msg, NULL);
	lm_message_unref(msg);

	pthread_mutex_unlock(&xmppmtx);
}

/**
 * Sends HTML help to specific command
 * @param jid		JabberID of recipient
 * @param mbody		Message body text
 */
void send_help_html(char* jid, int is_muc, char* mbody) {
	LmMessage*	msg;
	LmMessageNode *html, *htbody, *p;
	char* msg_arr[50][3];
	char* line_end;
	char *tab1, *tab2;
	char *in, *arr;
	int lines;
	int i = 0;
    char *jid_local;

    jid_local = NULL;
    //trim full MUC JID to bare MUC JID
    if(is_muc && strchr(jid, '/')) {
    	jid_local = alloca(strlen(jid));
    	strcpy(jid_local, jid);
    	*strchr(jid_local, '/') = '\0';
    }
    else
    	jid_local = jid;

	arr = malloc(strlen(mbody) + 1);
	if(arr == NULL)
		return;

	in = arr;

	strcpy(in, mbody);

	while((line_end = strchr(in, '\n')) != NULL) {
		*line_end = '\0';

		tab1 = strchr(in, '\t');
		if(tab1 == NULL)
			break;

		tab2 = strstr(in, "\t - ");
		if(tab2 == NULL)
			break;

		msg_arr[i][2] = alloca(100);
		strncpy(msg_arr[i][2], tab2 + 4, 100);
		msg_arr[i][2][99] = '\0';
		*tab2 = '\0';

		msg_arr[i][1] = alloca(100);
		strncpy(msg_arr[i][1], tab1 + 1, 95);
		msg_arr[i][1][95] = '\0';
		strcat(msg_arr[i][1], "    ");
		*tab1 = '\0';

		msg_arr[i][0] = alloca(25);
		strncpy(msg_arr[i][0], in, 20);
		msg_arr[i][0][20] = '\0';
		strcat(msg_arr[i][0], "    ");

		i++;
		if(i >= 50)
			break;

		in = line_end + 1;
	}

	lines = i;

	pthread_mutex_lock(&xmppmtx);
	msg = lm_message_new_with_sub_type(jid_local, LM_MESSAGE_TYPE_MESSAGE, is_muc?LM_MESSAGE_SUB_TYPE_GROUPCHAT:LM_MESSAGE_SUB_TYPE_CHAT);
	lm_message_node_add_child(msg->node, "body", mbody);

	html = lm_message_node_add_child(msg->node, "html", NULL);
	lm_message_node_set_attribute(html, "xmlns", "http://jabber.org/protocol/xhtml-im");
	htbody = lm_message_node_add_child(html, "body", NULL);
	lm_message_node_set_attribute(htbody, "xmlns", "http://www.w3.org/1999/xhtml");
	lm_message_node_set_attribute(htbody, "lang", "en");
	p = lm_message_node_add_child(htbody, "p", NULL);

	for(i = 0; i < lines; i++) {
		lm_message_node_add_child(p, "br", NULL);
		lm_message_node_add_child(p, "strong", msg_arr[i][0]);
		lm_message_node_add_child(p, "em", msg_arr[i][1]);
		lm_message_node_add_child(p, "span", msg_arr[i][2]);
	}

	lm_connection_send(xmpp_conn, msg, NULL);
	lm_message_unref(msg);
	pthread_mutex_unlock(&xmppmtx);

	free(arr);
}

/**
 * Exits the MUC room
 * @param room_jid	JID of the room to exit, bare or with some nickname (will be trimmed)
 */
void xmpp_muc_exit_room(char* jid) {
	LmMessage* m;
	char *muc_room_bare_jid, *my_full_room_jid;

	PRINTF_XMPP_GREEN("Exiting MUC room");

	muc_room_bare_jid = NULL;
    //trim full MUC JID to bare MUC JID
    if(strchr(jid, '/')) {
    	muc_room_bare_jid = alloca(strlen(jid));
    	strcpy(muc_room_bare_jid, jid);
    	*strchr(muc_room_bare_jid, '/') = '\0';
    }
    else
    	muc_room_bare_jid = jid;

	my_full_room_jid = alloca(strlen(muc_room_bare_jid) + 1 + strlen(birdbot_jid) + 1);
	sprintf(my_full_room_jid, "%s/%s", muc_room_bare_jid, birdbot_jid);

	pthread_mutex_lock(&xmppmtx);
	m = lm_message_new_with_sub_type(my_full_room_jid, LM_MESSAGE_TYPE_PRESENCE, LM_MESSAGE_SUB_TYPE_UNAVAILABLE);
	lm_connection_send(xmpp_conn, m, NULL);
	pthread_mutex_unlock(&xmppmtx);
	lm_message_unref(m);
}

/**
 * Processes incoming message from XMPP and sends data to BIRD socket
 * @param jid		JabberID of sender (chat), Full room JabberID with nickname (MUC)
 * @param cmdtext	Message body text
 * @param auth_lvl	Authentication level of user with given JID (1 = Restricted, 2 = Superuser)
 * @return			0 = OK, -1 = ERROR
 */
int process_cmd(char* sender_jid, char* cmdtext, int auth_lvl, int is_muc) {
	conn_t* conn;
	char* jid;
	char* s;
	int ambig_expansion = 0;
	char* ptr;

	jid = sender_jid;

	//if full occupant jid is passed in MUC mode, trim it to bare room jid
	if(is_muc && ((ptr = strchr(sender_jid, '/')) != NULL)) {
		jid = alloca(ptr - sender_jid + 1);
		strncpy(jid, sender_jid, ptr - sender_jid);
		jid[ptr - sender_jid] = '\0';
	}

	PRINTF_XMPP("JID trimmed to: %s", jid);

	conn = find_connection(jid);

	if (lastnb(cmdtext, strlen(cmdtext)) == '?')
	{
		char* c = cmd_help(cmdtext, strlen(cmdtext));
		send_help_html(jid, is_muc, c);
		free(c);

		return 0;
	}

	//lowercase first command letter
	if((cmdtext[0] >= 'A') && (cmdtext[0] <= 'Z'))
		cmdtext[0] += 'a' - 'A';

	//handle MUC kick command
	if(is_muc && (strncmp(cmdtext, "muckick ", 8) == 0)) {
		if(strcmp(strchr(cmdtext, ' ') + 1, birdbot_jid) == 0) {
			send_message(jid, 1, "See ya!");
			xmpp_muc_exit_room(jid);

			if(conn != NULL) {
				connection_stop(conn);
			}
		}
		return 0;
	}

	printf("processing command: %s\n", cmdtext);

	s = cmd_expand(cmdtext, &ambig_expansion);

	if(s == NULL) {
		send_message(jid, is_muc, "No such command. Press `?' for help.");
		return 0;
	}

	if(ambig_expansion) {
		send_message(jid, is_muc, s);
		free(s);
		return 0;
	}

	if(strcmp(s, "haltbot") == 0) {
		if(auth_lvl == 2) {
			free(s);
			exit_clean(0); //program end
		}
		else {
			send_message(jid, is_muc, "Access denied.");
			free(s);
			return 0;
		}
	}

	if(strcmp(s, "help") == 0) {
		send_message(jid, is_muc, "Use `?' for context-sensitive help.");
		free(s);
		return 0;
	}

	if(conn == NULL) {
		if(strcmp(s, "connect") == 0) {
			if(connection_new(jid, is_muc) != 0) {
				send_message(jid, is_muc, "Error connecting to BIRD socket.");
				free(s);
				return -1;
			}
			else {
				send_message(jid, is_muc, "Connected.");
			}
		}
		else {
			send_message(jid, is_muc, "Not connected. Write 'connect' to connect.");
		}
	}
	else { //we are connected room_jid BIRD socket
		if(strcmp(s, "connect") == 0) {
			send_message(jid, is_muc, "Already connected.");
		}
		else if((strncmp(s, "exit", 4) == 0) || (strncmp(s, "quit", 4) == 0)) {
			if(is_muc) {
				ptr = strchr(s, ' ');
				if((ptr == NULL) || (strcmp(ptr + 1, birdbot_jid) == 0)) {
					send_message(jid, is_muc, "Bye.");
					xmpp_muc_exit_room(jid);
					connection_stop(conn);
				}
			}
			else {
				connection_stop(conn);
				send_message(jid, is_muc, "Bye.");
			}
		}
		else {
			if(conn->bird_ready) {
				int len;
				len = strlen(s);
				s[len] = '\n';	//append newline char
				s[++len] = '\0'; //s allocated with enough free space
				printf("Sending: %s\n", s);
				if(write(conn->sock_fd, s, len) <= 0) {
					puts("Socket write error.");
				}
			}
			else {
				puts("BIRD not ready");
			}
		}
	}

	free(s);
	return 0;
}


/**
 * Gets user authentication level
 * @param jid	JabberID of user
 * @return		0 = Not allowed, 1 = Restricted user, 2 = Superuser
 */
int check_user_auth(char* jid, int is_muc) {
	int user_auth_lvl = 0;
	char* ptr;
	char *bare_jid, *nickname;
	int barejid_len;
	int i;

	ptr = strchr(jid, '/'); //trim extended jid

	/*if(is_muc) {
		if(ptr == NULL) {
			return 0;
		}
		else {
			barejid_len = strlen(ptr + 1);
			bare_jid = ptr + 1;
		}
	}
	else {*/
		if(ptr == NULL) {
			barejid_len = strlen(jid);
		}
		else {
			barejid_len = ptr - jid;
		}
		bare_jid = alloca(barejid_len + 1);
		strncpy(bare_jid, jid, barejid_len);
		bare_jid[barejid_len] = '\0';
	//}

	if((barejid_len < 3) || (strchr(jid, '@') == NULL)) //malformed JID (shortest possible: a@a)
		return 0;

	for(i = 0; superusers[i] != NULL; i++) {
		if(strcmp(bare_jid, superusers[i]) == 0) {
			user_auth_lvl = 2;
			break;
		}
	}

	if(user_auth_lvl == 0) {
		for(i = 0; restricted_users[i] != NULL; i++) {
			if(strcmp(bare_jid, restricted_users[i]) == 0) {
				user_auth_lvl = 1;
				break;
			}
		}
	}

	//if MUC, both room name and nickname must be specified in config file
	//to prevent bot reactions to messages from other bots (xmpp infinite loops)
	if(is_muc && (user_auth_lvl != 0)) {
		if(ptr == NULL)
			 return user_auth_lvl;	//if bare MUC room jid, verify only this bare jid

		nickname = ptr + 1;
		user_auth_lvl = 0;

		for(i = 0; superusers[i] != NULL; i++) {
			if(strcmp(nickname, superusers[i]) == 0) {
				user_auth_lvl = 2;
				break;
			}
		}

		if(user_auth_lvl == 0) {
			for(i = 0; restricted_users[i] != NULL; i++) {
				if(strcmp(nickname, restricted_users[i]) == 0) {
					user_auth_lvl = 1;
					break;
				}
			}
		}
	}

	return user_auth_lvl;
}

/**
 * SIGTERM handler
 */
void sigterm_handler(int n) {
	exit_clean(0);
}

/**
 * Reads BIRDbot setting from config file
 * @param path	File path
 * @return		0 = OK, -1 = ERROR
 */
int load_config(char* path) {
	///parse config file
	FILE* fconf;
	char line[101];
	char* lptr;
	char* ptr;
	int i = 0;

	memset(superusers, 0, sizeof(superusers));
	memset(restricted_users, 0, sizeof(restricted_users));

	fconf = fopen(path, "rt");
	if(fconf == NULL) {
		puts("Cannot open config file!");
		return -1;
	}

	while(fgets(line, 100, fconf) != NULL) {
		if(strcmp(skipblank(line), "XMPP:\n") == 0)
			break;
	}

	while(fgets(line, 100, fconf) != NULL) {
		lptr = skipblank(line);

		if(lptr[0] == '#')
			continue;
		if((lastnb(lptr, strlen(lptr) - 1) == ':') || (lptr[0] == '\n') || (lptr[0] == '\r'))
			break;

		if((birdbot_jid == NULL) && (strncmp(lptr, "JID=", 4) == 0)) {
			birdbot_jid = malloc(strlen(lptr));
			strncpy(birdbot_jid, lptr + 4, strlen(lptr) - 4 - 1);
			birdbot_jid[strlen(lptr) - 4 - 1] = '\0';
		}
		else if((birdbot_pw == NULL) && (strncmp(lptr, "PASS=", 5) == 0)) {
			birdbot_pw = malloc(strlen(lptr));
			strncpy(birdbot_pw, lptr + 5, strlen(lptr) - 5 - 1);
			birdbot_pw[strlen(lptr) - 5 - 1] = '\0';
		}
	}

	rewind(fconf);

	i = 0;
	while(fgets(line, 100, fconf) != NULL) {
		if(strcmp(skipblank(line), "SUPERUSERS:\n") == 0)
			break;
	}

	while(fgets(line, 100, fconf) != NULL) {
		lptr = skipblank(line);

		if(lptr[0] == '#')
			continue;
		if((lastnb(lptr, strlen(lptr) - 1) == ':') || (lptr[0] == '\n') || (lptr[0] == '\r'))
			break;

		ptr = malloc(strlen(lptr));
		strncpy(ptr, lptr, strlen(lptr)-1);
		ptr[strlen(lptr)-1] = '\0';
		if(i < 99) {
			superusers[i] = ptr;
			i++;
		}
	}

	rewind(fconf);

	i = 0;
	while(fgets(line, 100, fconf) != NULL) {
		if(strcmp(skipblank(line), "RESTRICTED:\n") == 0)
			break;
	}

	while(fgets(line, 100, fconf) != NULL) {
		lptr = skipblank(line);

		if(lptr[0] == '#')
			continue;
		if((lastnb(lptr, strlen(lptr) - 1) == ':') || (lptr[0] == '\n') || (lptr[0] == '\r'))
			break;

		ptr = malloc(strlen(lptr));
		strncpy(ptr, lptr, strlen(lptr)-1);
		ptr[strlen(lptr)-1] = '\0';
		if(i < 99) {
			restricted_users[i] = ptr;
			i++;
		}
	}

	return 0;
}

/**
 * Prints BIRDbot configuration, for debugging purposes
 */
void print_config(void) {
	char** ptr2;

	printf("Birdbot JID: %s\n", birdbot_jid);
	printf("Birdbot pass: %s\n", birdbot_pw);

	ptr2 = superusers;
	puts("Superusers:");
	while(*ptr2 != NULL) {
		puts(*ptr2);
		ptr2++;
	}

	ptr2 = restricted_users;
	puts("Restricted users:");
	while(*ptr2 != NULL) {
		puts(*ptr2);
		ptr2++;
	}
}

/**
 * Gets username from JID
 * @param jid	JabberID of user
 * @return		Username (newly allocated), NULL = ERROR
 */
gchar* jid_get_name(const gchar *jid) {
    const gchar *ch;

    g_return_val_if_fail(jid != NULL, NULL);

    ch = strchr(jid, '@');
    if(!ch)
    	return NULL;

    return g_strndup(jid, ch - jid);
}

/**
 * Gets server domain from JID
 * @param jid	JabberID of user
 * @return		Pointer to first character of server domain in the JID, NULL = ERROR
 */
char* jid_get_server(const char* jid) {
	char* ptr;
	ptr = strchr(jid, '@');
	if(ptr != NULL)
		return ptr + 1;
	else
		return NULL;
}

/**
 * Callback, for logging users to XMPP server
 */
void xmpp_conn_auth_handler(LmConnection *connection, gboolean success, gpointer user_data) {
	if (success) {
		LmMessage *m;

		PRINTF_XMPP_GREEN("Authenticated successfully");

		m = lm_message_new_with_sub_type(NULL, LM_MESSAGE_TYPE_PRESENCE, LM_MESSAGE_SUB_TYPE_AVAILABLE);
		lm_connection_send(connection, m, NULL);
		PRINTF_XMPP("Sent presence message: %s", lm_message_node_to_string(m->node));
		lm_message_unref(m);
	}
	else {
		PRINTF_XMPP_RED("Failed to authenticate");
		g_main_loop_quit(main_loop);
	}
}

/**
 * Callback, manages XMPP server connection events
 */
void xmpp_conn_open_handler(LmConnection *connection, gboolean success, gpointer user_data) {
	if(success) {
		gchar *user;

		user = jid_get_name(birdbot_jid);
		lm_connection_authenticate(connection, user, birdbot_pw, "test-lm", xmpp_conn_auth_handler, NULL, FALSE,  NULL);
		g_free(user);

		PRINTF_XMPP("Sent authentication message\n");
	} else {
		PRINTF_XMPP("Failed to connect\n");
		g_main_loop_quit(main_loop);
	}
}

/**
 * Callback, manages XMPP server connection events
 */
void xmpp_conn_close_handler(LmConnection *connection, LmDisconnectReason  reason, gpointer user_data) {
    const char *str;

    switch (reason) {
    case LM_DISCONNECT_REASON_OK:
        str = "LM_DISCONNECT_REASON_OK";
        break;
    case LM_DISCONNECT_REASON_PING_TIME_OUT:
        str = "LM_DISCONNECT_REASON_PING_TIME_OUT";
        break;
    case LM_DISCONNECT_REASON_HUP:
        str = "LM_DISCONNECT_REASON_HUP";
        break;
    case LM_DISCONNECT_REASON_ERROR:
        str = "LM_DISCONNECT_REASON_ERROR";
        break;
    case LM_DISCONNECT_REASON_UNKNOWN:
    default:
        str = "LM_DISCONNECT_REASON_UNKNOWN";
        break;
    }

    PRINTF_XMPP_YELLOW("Disconnected, reason: %d->'%s'\n", reason, str);
    g_main_loop_quit(main_loop);
}

/**
 * Callback for processing incoming XMPP messages
 */
LmHandlerResult xmpp_message_handler(LmMessageHandler *handler, LmConnection *connection, LmMessage *m, gpointer user_data) {
	LmMessage* reply;
	LmMessageNode *x, *inv, *decline, *history;
	char *from, *to;
	char* muc_room_jid;
	//char* jid_separator;
	char *intext = NULL;
	int user_auth_lvl = 0; // 0 = not authorized, 1 = restricted, 2 = superuser
	int is_muc = 0;
	conn_t* conn;

	printf("received msg = \n%s\n",lm_message_node_to_string(m->node));

	//trash offline messages
	if(lm_message_node_get_child(m->node, "delay") != NULL)
		return LM_HANDLER_RESULT_REMOVE_MESSAGE;

	//process MUC room invitation
	x = lm_message_node_get_child(m->node, "x");
	if(x != NULL) {
		inv = lm_message_node_get_child(x, "invite");
		if(inv != NULL) {
			muc_room_jid = (char*)lm_message_node_get_attribute(m->node, "from");
			from = (char*)lm_message_node_get_attribute(inv, "from");
			PRINTF_XMPP("Processing MUC invitation from %s", from);

			user_auth_lvl = check_user_auth(muc_room_jid, 0);
			if(user_auth_lvl != 2) {
				//refuse invitation
				puts(from);
				PRINTF_XMPP_YELLOW("Refused :-(");
				reply = lm_message_new(muc_room_jid, LM_MESSAGE_TYPE_MESSAGE);
				x = lm_message_node_add_child(reply->node, "x", NULL);
				lm_message_node_set_attribute(x, "xmlns", "http://jabber.org/protocol/muc#user");
				decline = lm_message_node_add_child(x, "decline", NULL);
				lm_message_node_set_attribute(decline, "to", from);
				lm_message_node_add_child(decline, "reason", "Invitation refused: Not authorized!");
				lm_connection_send(xmpp_conn, reply, NULL);
				lm_message_unref(reply);
			}
			else {
				PRINTF_XMPP_GREEN("Accepted :-)");
				//accept invitation (send presence), create connection
				to = alloca(strlen(muc_room_jid) + 1 + strlen(birdbot_jid) + 1);
				sprintf(to, "%s/%s", muc_room_jid, birdbot_jid);
				reply = lm_message_new(to, LM_MESSAGE_TYPE_PRESENCE);
				x = lm_message_node_add_child(reply->node, "x", NULL);
				lm_message_node_set_attribute(x, "xmlns", "http://jabber.org/protocol/muc");
				history = lm_message_node_add_child(x, "history", NULL);
				//disable room history
				lm_message_node_set_attribute(history, "maxchars", "0");
				lm_connection_send(xmpp_conn, reply, NULL);
				lm_message_unref(reply);

				connection_new(muc_room_jid, 1);
				conn = find_connection(muc_room_jid);
				if(conn != NULL) {
					conn->muc.muc_state = XMPP_MUC_STATE_AWAITING_PRESENCES;
				}

			}
			return LM_HANDLER_RESULT_REMOVE_MESSAGE;
		}
	}

	//process normal message
	if(lm_message_node_get_child(m->node, "body") == NULL)
		return LM_HANDLER_RESULT_REMOVE_MESSAGE;

	if((lm_message_node_get_attribute(m->node, "type") != NULL) && !strcmp(lm_message_node_get_attribute(m->node, "type"), "error"))
		return LM_HANDLER_RESULT_REMOVE_MESSAGE;

	from = (char*)lm_message_node_get_attribute(m->node, "from");

    if(lm_message_node_get_child(m->node, "body")->value != NULL)
    	intext = (char*)lm_message_node_get_value(lm_message_node_get_child(m->node, "body"));

    PRINTF_XMPP_GREEN("Incoming message from %s: %s", from, intext);

	if(lm_message_get_sub_type(m) == LM_MESSAGE_SUB_TYPE_GROUPCHAT) {
		is_muc = 1;
		user_auth_lvl = check_user_auth(from, is_muc);

		//filter messages without nickname specified
		if(strchr(from, '/') == NULL)
			return LM_HANDLER_RESULT_REMOVE_MESSAGE;

		PRINTF_XMPP("Checking MUC auth: %s, lvl = %d", from, user_auth_lvl);
		if(user_auth_lvl != 0) {
			//we are an authorized user
			process_cmd(from, intext, user_auth_lvl, is_muc);
		}
	}
	else {
		user_auth_lvl = check_user_auth(from, is_muc);
		if(user_auth_lvl == 0) {
			send_message(from, is_muc, "Not authorized.");
		}
		else {
			//we are an authorized user
			process_cmd(from, intext, user_auth_lvl, is_muc);
		}
	}

    return LM_HANDLER_RESULT_REMOVE_MESSAGE;
}

/**
 * Callback, authorizes allowed users to view presence status of BIRDbot
 */
LmHandlerResult xmpp_presence_handler(LmMessageHandler *handler, LmConnection *connection, LmMessage *m, gpointer user_data) {
	LmMessage* msub;
	LmMessageNode *x;
	char* from;
	char *jid_separator, *jid;
	LmMessageSubType subtype;
	conn_t* conn;

	//printf("XMPP incomimg presence = \n%s\n", lm_message_node_to_string(m->node));
	from = (char*)lm_message_node_get_attribute(m->node, "from");

	//handle MUC self-presence
	if((jid_separator = strchr(from, '/')) != NULL) {
		if(strcmp(jid_separator + 1, birdbot_jid) == 0) {
			x = lm_message_node_get_child(m->node, "x");
			if(x != NULL) {
				if(strncmp(lm_message_node_get_attribute(x, "xmlns"), "http://jabber.org/protocol/muc",
						strlen("http://jabber.org/protocol/muc")) == 0) {
					jid = xmpp_trim_jid_by_slash(from);
					conn = find_connection(jid);
					free(jid);
					if(conn != NULL) {
						conn->muc.muc_state = XMPP_MUC_STATE_WORKING;
					}
				}
			}
		}
	}


	pthread_mutex_lock(&xmppmtx);
	if(lm_message_get_sub_type(m) == LM_MESSAGE_SUB_TYPE_SUBSCRIBE) {
		if(check_user_auth(from, 0) > 0) {
			subtype = LM_MESSAGE_SUB_TYPE_SUBSCRIBED;
			PRINTF_XMPP_GREEN("User %s requested authorization, allowed.\n", from);
		}
		else {
			subtype = LM_MESSAGE_SUB_TYPE_UNSUBSCRIBED;
			PRINTF_XMPP_YELLOW("User %s requested authorization, rejected.\n", from);
		}

		msub = lm_message_new_with_sub_type(from, LM_MESSAGE_TYPE_PRESENCE, subtype);
		lm_connection_send(xmpp_conn, msub, NULL);
		lm_message_unref(msub);
	}
	pthread_mutex_unlock(&xmppmtx);

	return LM_HANDLER_RESULT_REMOVE_MESSAGE;
}

LmHandlerResult xmpp_iq_handler(LmMessageHandler *handler, LmConnection *connection, LmMessage *m, gpointer user_data) {
	LmMessage* msub;
	char *from, *data, *id;

	pthread_mutex_lock(&xmppmtx);

	if(lm_message_get_sub_type(m) == LM_MESSAGE_SUB_TYPE_GET) {
		from = (char*)lm_message_node_get_attribute(m->node, "from");
		id = (char*)lm_message_node_get_attribute(m->node, "id");

		if(lm_message_node_get_child(m->node, "ping") != NULL) {
			data = lm_message_node_to_string(m->node);
			PRINTF_XMPP("Incoming XMPP ping: %s\n", data);
			g_free(data);

			msub = lm_message_new_with_sub_type(from, LM_MESSAGE_TYPE_IQ, LM_MESSAGE_SUB_TYPE_RESULT);
			lm_message_node_set_attribute(msub->node, "id", id);
			lm_connection_send(xmpp_conn, msub, NULL);
			lm_message_unref(msub);
		}
	}
	else if(lm_message_get_sub_type(m) == LM_MESSAGE_SUB_TYPE_RESULT) {
		data = lm_message_node_to_string(m->node);
		PRINTF_XMPP("Incoming XMPP result: %s\n", data);
		g_free(data);
	}
	pthread_mutex_unlock(&xmppmtx);

	return LM_HANDLER_RESULT_REMOVE_MESSAGE;
}

/**
 * XMPP whitespace keepalive, sends space character to server every 5 minutes
 */
void* xmpp_keep_alive_thread(void* args) {
	LmMessage* msg;
	LmMessageNode* ping;
	int sresult;
	GError* err;
	time_t t;
	fd_set fds;
	struct tm tm;
	struct timeval tv;

	while(1) {
		//sleep(XMPP_KEEPALIVE_INTERVAL);
		FD_ZERO(&fds);
		FD_SET(xmpp_keepalive_termpipe[PIP_RD], &fds);
		tv.tv_sec = XMPP_KEEPALIVE_INTERVAL;
		tv.tv_usec = 0;
		select(xmpp_keepalive_termpipe[PIP_RD] + 1, &fds, NULL, NULL, &tv);
		if(FD_ISSET(xmpp_keepalive_termpipe[PIP_RD], &fds))
			break;

		pthread_mutex_lock(&xmppmtx);
		msg = lm_message_new_with_sub_type(jid_get_server(birdbot_jid), LM_MESSAGE_TYPE_IQ, LM_MESSAGE_SUB_TYPE_GET);
		lm_message_node_set_attribute(msg->node, "id", "client-ping");
		ping = lm_message_node_add_child(msg->node, "ping", NULL);
		lm_message_node_set_attribute(ping, "xmlns", "urn:xmpp:ping");
		sresult = lm_connection_send(xmpp_conn, msg, &err);
		lm_message_unref(msg);
		t = time(NULL);
		tm = *localtime(&t);
		PRINTF_XMPP("[%02d:%02d] Sending keepalive\n", tm.tm_hour, tm.tm_min);
		if(!sresult) {
			PRINTF_XMPP_RED("Keepalive send failed, status: [%d] %s\n", err->code, err->message);
			g_free(err);
		}
		pthread_mutex_unlock(&xmppmtx);
	}

	PRINTF_XMPP("keepalive thread ended.");
	return NULL;
}

/**
 * Callback, handles XMPP SSL events
 */
LmSSLResponse xmpp_ssl_handler(LmSSL *ssl, LmSSLStatus status, gpointer ud) {
	PRINTF_XMPP("SSL status %d\n", status);

    switch(status) {
    case LM_SSL_STATUS_NO_CERT_FOUND:
    	PRINTF_XMPP("No certificate found!\n");
        break;
    case LM_SSL_STATUS_UNTRUSTED_CERT:
    	PRINTF_XMPP("Certificate is not trusted!\n");
        break;
    case LM_SSL_STATUS_CERT_EXPIRED:
    	PRINTF_XMPP("Certificate has expired!\n");
        break;
    case LM_SSL_STATUS_CERT_NOT_ACTIVATED:
    	PRINTF_XMPP("Certificate has not been activated!\n");
        break;
    case LM_SSL_STATUS_CERT_HOSTNAME_MISMATCH:
    	PRINTF_XMPP("Certificate hostname does not match expected hostname!\n");
        break;
    case LM_SSL_STATUS_CERT_FINGERPRINT_MISMATCH: {
        //const char *fpr = lm_ssl_get_fingerprint (ssl);
    	PRINTF_XMPP("Certificate fingerprint does not match expected fingerprint!\n");
        //print both fingerprints
        break;
    }
    case LM_SSL_STATUS_GENERIC_ERROR:
    	PRINTF_XMPP("Generic SSL error!\n");
        break;
    }

    return LM_SSL_RESPONSE_CONTINUE;
}

void display_opt_help(const struct option* opts, const char* helptext[]) {
	int i = 0;
	puts("Send commands to BIRD via XMPP.\n");
	while(opts->name != NULL) {
		printf("-%c | --%s\n", opts->val, opts->name);
		if(helptext[i] != NULL) {
			printf("%s\n\n", helptext[i]);
			i++;
		}
		opts++;
	}
}

int main(int argc, char **argv)
{
    LmMessageHandler *handler;
    gboolean          result;
    GError           *error = NULL;
    static char* xmpp_domain;

    char opt;
    int longopts_idx;
    const struct option longopts[] = {
    		{"debug", no_argument, NULL, 'd'},
			{"force-ipv4", no_argument, NULL, '4'},
			{"nossl", no_argument, NULL, 'n'},
			{"jid", required_argument, NULL, 'j'},
			{"pass", required_argument, NULL, 'p'},
			{"socket", required_argument, NULL, 's'},
			{"help", no_argument, NULL, 'h'},
			{NULL, 0, NULL, 0}
    };

    const char* opthelp[] = {
    		"Debug mode. Program will display debugging information instead of going to background.",
			"Force IPv4 resolution of XMPP server hostname.",
			"Disable use of SSL connection with XMPP server.",
			"Specify BIRDbot's bare JID. This option overrides JID set in the configuration file.",
			"Specify BIRDbot's XMPP password. This option overrides password set in the configuration file.",
			"Set BIRD control socket.",
			"Display this help and exit.",
			NULL
    };

    pid_t pid, sid;
    int lockfile;
    int is_daemon = 1;
    int xmpp_force_ipv4 = 0;
    int xmpp_use_ssl = 1;

    struct sigaction action;
    memset(&action, 0, sizeof(struct sigaction));
    action.sa_handler = sigterm_handler;
    sigaction(SIGINT, &action, NULL);
    sigaction(SIGTERM, &action, NULL);

    birdbot_jid = NULL;
    birdbot_pw = NULL;
    strncpy(bird_socket, PATH_CONTROL_SOCKET, sizeof(bird_socket) - 1);
    bird_socket[sizeof(bird_socket) - 1] = '\0';

    //parse command line parameters
    while((opt = getopt_long(argc, argv, "d4nhj:p:s:", longopts, &longopts_idx)) != -1) {
    	switch(opt) {
    		case 'd': {
    			is_daemon = 0;
    			break;
    		}
    		case '4': {
    			xmpp_force_ipv4 = 1;
    			break;
    		}
    		case 'n': {
    			xmpp_use_ssl = 0;
    			break;
    		}
    		case 'j': {
    		    birdbot_jid = malloc(strlen(optarg) + 1);
    		    strcpy(birdbot_jid, optarg);
    		    break;
    		}
    		case 'p': {
    			birdbot_pw = malloc(strlen(optarg) + 1);
    			strcpy(birdbot_pw, optarg);
    			break;
    		}
    		case 's': {
    			strncpy(bird_socket, optarg, sizeof(bird_socket) - 1);
    			bird_socket[sizeof(bird_socket) - 1] = '\0';
    			break;
    		}
    		case 'h': {
    			display_opt_help(longopts, opthelp);
    			puts("Exiting.");
    			return 1;
    			break;
    		}
    		default: {
    			//unknown option, do not continue
    			return -1;
    			break;
    		}
    	}
    }

    //load configuration
    if(load_config(PATH_CONFIG) != 0)
    	return -1;

    //print configuration
    if(!is_daemon)
    	print_config();

    //validate configuration
    if(birdbot_jid == NULL) {
    	puts("You must specify BIRDbot's JID in config file or as command line argument.");
    	exit_clean(-1);
    }
    else {
    	if(birdbot_pw == NULL) {
    		//if(!is_daemon) {
    			int attempts = 3;
    			birdbot_pw = malloc(31);
    			do {
    				printf("Enter XMPP account password: ");
    			}while((scanf("%30s", birdbot_pw) != 1) && --attempts);
    			if(attempts == 0)
    				exit_clean(-1);
    		//}
    		//else
    		//	exit_clean(-1);
    	}
    }

	//daemonize
    if(is_daemon) {
    	pid = fork();
    	if(pid < 0)
    		return -1;

    	if(pid > 0)
    		return 0;

    	umask(0);

    	sid = setsid();
    	if(sid < 0)
    		return -1;

    	if ((chdir("/")) < 0)
    		return -1;

    	pid = fork();
    	if(pid < 0)
    		return -1;

    	if(pid > 0)
    		return 0;
    }

    //ensure single instance
    lockfile = open(PATH_LOCKFILE, O_WRONLY | O_CREAT, "0666");
    if(lockfile < 0) {
    	puts("Error opening lockfile, exiting. (Is running as root?)");
    	exit_clean(-1);
    }

    if(lockf(lockfile, F_TLOCK, 0) != 0) {
    	puts("Birdbot already running (lockfile exists), exiting.");
    	exit_clean(1);
    }

    //close standard file descriptors
    if(is_daemon) {
        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);

        open("/dev/null", O_RDWR);
        if(dup(0) == -1)
        	exit_clean(-1);
        if(dup(0) == -1)
        	exit_clean(-1);
    }

    cmd_build_tree();

    //initialize XMPP
    xmpp_domain = jid_get_server(birdbot_jid);
    if(xmpp_domain == NULL) {
    	printf("Invalid XMPP bot jid: %s\n", birdbot_jid);
    	exit_clean(-1);
    }


    //resolve XMPP server's SRV record from DNS
    char ns_buf[512];
    char xmpp_srv_nsrecord[256];
    char xmpp_srv_hostname[128];
	char xmpp_ip[64];
    int len;
    ns_msg msg;
    ns_rr rr;
    struct addrinfo aihints;
    struct addrinfo *aires, *aii;

    res_init();

    strcpy(xmpp_srv_nsrecord, "_xmpp-client._tcp.");
    strncat(xmpp_srv_nsrecord, xmpp_domain, sizeof(xmpp_srv_nsrecord) - sizeof("_xmpp-client._tcp."));

    len = res_query(xmpp_srv_nsrecord, ns_c_any, ns_t_srv, (u_char*)ns_buf, sizeof(ns_buf));
    if(len < 0) {
    	puts("NS: SRV record resolution failed.");
    	exit_clean(-1);
    }

    ns_initparse((u_char*)ns_buf, len, &msg);

    //len = ns_msg_count(msg, ns_s_an); //len = number of records found

    char* c;
    ns_parserr(&msg, ns_s_an, 0, &rr);	//0 = we take the first record
    ns_sprintrr(&msg, &rr, NULL, NULL, xmpp_srv_nsrecord, sizeof(xmpp_srv_nsrecord));

    c = strrchr(xmpp_srv_nsrecord, '.');
    if((c != NULL) && (*(c + 1) == '\0')) {
    	*c = '\0';
    	c = strrchr(xmpp_srv_nsrecord, ' ');
    	if(c != NULL) {
    		strncpy(xmpp_srv_hostname, c + 1, sizeof(xmpp_srv_hostname) - 1);
    		xmpp_srv_hostname[sizeof(xmpp_srv_hostname) - 1] = '\0';
    	}
    }

    printf("NS: Resolved hostname (SRV) of XMPP server: %s\n", xmpp_srv_hostname);

    xmpp_ip[0] = '\0';

    memset(&aihints, 0, sizeof(aihints));
    aihints.ai_family = AF_INET6;
    aihints.ai_socktype = SOCK_STREAM;

    /*if((getaddrinfo(xmpp_srv_hostname, "xmpp-client", &aihints, &aires) == 0) && (aires != NULL) && (!xmpp_force_ipv4)) {
    	for(aii = aires; aii != NULL; aii = aii->ai_next) {
    		if(getnameinfo(aii->ai_addr, aii->ai_addrlen, xmpp_ip, sizeof(xmpp_ip) - 1, NULL, 0, NI_NUMERICHOST) == 0) {
    			printf("NI: Using xmpp IPv6: %s\n", xmpp_ip);
    			break;
    		}
    	}
    	freeaddrinfo(aires);
    }
    else {*/
    	//Current version of libloudmouth does not support passing IPv6 as argument
    if(xmpp_force_ipv4) {
    	aihints.ai_family = AF_INET;
    	if((getaddrinfo(xmpp_srv_hostname, "xmpp-client", &aihints, &aires) == 0) && (aires != NULL)) {
    		for(aii = aires; aii != NULL; aii = aii->ai_next) {
    			if(getnameinfo(aii->ai_addr, aii->ai_addrlen, xmpp_ip, sizeof(xmpp_ip) - 1, NULL, 0, NI_NUMERICHOST) == 0) {
    				printf("NI: Using xmpp IPv4: %s\n", xmpp_ip);
    				break;
    			}
    		}
    		freeaddrinfo(aires);
    	}
    	else {
    		puts("NI: Cannot resolve xmpp server IP, exiting.");
    		exit_clean(-1);
    	}
    }
    //}

    if(xmpp_force_ipv4)
    	xmpp_conn = lm_connection_new(xmpp_ip);
    else
    	xmpp_conn = lm_connection_new(xmpp_srv_hostname);

    lm_connection_set_port(xmpp_conn, LM_CONNECTION_DEFAULT_PORT);
    lm_connection_set_jid(xmpp_conn, birdbot_jid);

    if(xmpp_use_ssl) {
        if(lm_ssl_is_supported()) {
        	LmSSL *ssl;
        	ssl = lm_ssl_new(NULL, (LmSSLFunction)xmpp_ssl_handler, NULL, NULL);
        	lm_ssl_use_starttls(ssl, TRUE, FALSE);
        	lm_connection_set_ssl(xmpp_conn, ssl);
        	lm_ssl_unref(ssl);
        }
        else {
        	PRINTF_XMPP_YELLOW("Warning. SSL is not available in current instalation of libloudmouth.");
        }
    }

    handler = lm_message_handler_new(xmpp_message_handler, NULL, NULL);
    lm_connection_register_message_handler(xmpp_conn, handler, LM_MESSAGE_TYPE_MESSAGE, LM_HANDLER_PRIORITY_NORMAL);
    lm_message_handler_unref(handler);

    handler = lm_message_handler_new(xmpp_presence_handler, NULL, NULL);
    lm_connection_register_message_handler(xmpp_conn, handler, LM_MESSAGE_TYPE_PRESENCE, LM_HANDLER_PRIORITY_NORMAL);
    lm_message_handler_unref(handler);

    handler = lm_message_handler_new(xmpp_iq_handler, NULL, NULL);
    lm_connection_register_message_handler(xmpp_conn, handler, LM_MESSAGE_TYPE_IQ, LM_HANDLER_PRIORITY_NORMAL);
    lm_message_handler_unref(handler);

    lm_connection_set_disconnect_function(xmpp_conn, xmpp_conn_close_handler, NULL, NULL);
    result = lm_connection_open(xmpp_conn, (LmResultFunction)xmpp_conn_open_handler, NULL, NULL, &error);

    if(!result) {
        printf("Opening xmpp_conn failed, error: %d->'%s'\n", error->code, error->message);
        g_free(error);
        exit_clean(-1);
    }

    if(pipe(xmpp_keepalive_termpipe) < 0)
    	return -1;
    pthread_create(&xmpp_keepalive_tid, NULL, xmpp_keep_alive_thread, NULL);
    pthread_detach(xmpp_keepalive_tid);

    main_loop = g_main_loop_new(NULL, FALSE);
    g_main_loop_run(main_loop);

    exit_clean(0);
    return 0;
}
