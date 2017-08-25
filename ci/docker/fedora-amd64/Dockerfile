FROM fedora:latest
RUN dnf -y upgrade
RUN dnf -y install \
	autoconf \
	flex \
	bison \
	pkgconfig \
	'readline-devel' \
	'pkgconfig(ncurses)' \
	gcc
