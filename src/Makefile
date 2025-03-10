CC = gcc
CFLAGS = -Wall -Wextra -g -O2
LDFLAGS = -lseccomp -lpthread -lcrypto -lm

SRCS = main.c daemon_utils.c file_monitor.c syscall_monitor.c process_analyzer.c \
	   syscall_filter.c response.c behavioral_analysis.c entropy_analysis.c \
	   process_relationship.c syscall_pattern.c hash_monitor.c
OBJS = $(SRCS:.c=.o)
TARGET = ransomguard

HEADERS = *.h

PREFIX = /usr/local
BINDIR = $(PREFIX)/bin
CONFDIR = /etc
CONFFILE = ransomguard.conf

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

install: $(TARGET)
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 $(TARGET) $(DESTDIR)$(BINDIR)
	install -d $(DESTDIR)$(CONFDIR)
	[ -f $(DESTDIR)$(CONFFILE) ] || install -m 644 $(CONFFILE) $(DESTDIR)$(CONFDIR)

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(TARGET)
	rm -f $(DESTDIR)$(CONFDIR)/$(CONFFILE)

clean:
	rm -f $(OBJS) $(TARGET)

test: $(TARGET)
	./$(TARGET) --watchdir=/tmp/test --no-daemon

debug: CFLAGS += -DDEBUG -O0
debug: clean all

memcheck: $(TARGET)
	valgrind --leak-check=full --show-leak-kinds=all ./$(TARGET) --watchdir=/tmp/test --no-daemon

.PHONY: all install uninstall clean test debug memcheck