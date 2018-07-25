#!/bin/bash

CC=gcc
CFLAGS='-O3 -Wall -fmessage-length=0 -g3 -DDEBUG'
PUSH_SOURCES='push_log.c push_window.c push.c'

$CC $CFLAGS $PUSH_SOURCES -lpcap -o push
