# Makefile for RansomGuard
CC = gcc
CFLAGS = -Wall -Wextra -g -O2
LDFLAGS = -lseccomp

# Sources and objects
SRCS = main.c daemon_utils.c file_monitor.c syscall_monitor.c process_analyzer.c syscall_filter.c response.c
OBJS = $(SRCS:.c=.o)
TARGET = ransomguard

# Install paths
PREFIX = /usr/local
BINDIR = $(PREFIX)/bin
CONFDIR = /etc

all: $(TARGET)

$(TARGET): $(OBJS)
    $(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
    $(CC) $(CFLAGS) -c $< -o $@

install: $(TARGET)
    install -d $(DESTDIR)$(BINDIR)
    install -m 755 $(TARGET) $(DESTDIR)$(BINDIR)
    install -d $(DESTDIR)$(CONFDIR)
    [ -f $(DESTDIR)$(CONFDIR)/ransomguard.conf ] || install -m 644 ransomguard.conf $(DESTDIR)$(CONFDIR)

uninstall:
    rm -f $(DESTDIR)$(BINDIR)/$(TARGET)
    rm -f $(DESTDIR)$(CONFDIR)/ransomguard.conf

clean:
    rm -f $(OBJS) $(TARGET)

.PHONY: all install uninstall clean