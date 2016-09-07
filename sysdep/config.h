/*
 *	This file contains all parameters dependent on the
 *	operating system and build-time configuration.
 */

#ifndef _BIRD_CONFIG_H_
#define _BIRD_CONFIG_H_

/* Include parameters determined by configure script */
#include "sysdep/autoconf.h"

/* BIRD version */
#ifdef GIT_VERSION
#define BIRD_VERSION GIT_VERSION
#else
#define BIRD_VERSION "1.6.0"
#endif

/* Include OS configuration file as chosen in autoconf.h */
#include SYSCONF_INCLUDE

#ifndef MACROS_ONLY

/*
 *  Of course we could add the paths to autoconf.h, but autoconf
 *  is stupid and puts make-specific substitutious to the paths.
 */
#include "sysdep/paths.h"

/* Types */
typedef signed INTEGER_8 s8;
typedef unsigned INTEGER_8 u8;
typedef INTEGER_16 s16;
typedef unsigned INTEGER_16 u16;
typedef INTEGER_32 s32;
typedef unsigned INTEGER_32 u32;
typedef INTEGER_64 s64;
typedef unsigned INTEGER_64 u64;
typedef u8 byte;
typedef u16 word;
typedef unsigned int uint;

#endif

#endif
