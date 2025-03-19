CC = gcc
CFLAGS = -Wall -Wextra -Werror -g -O2 -D_GNU_SOURCE -fstack-protector-strong
LDFLAGS = -lseccomp -lpthread -lcrypto -lm -lrt

SRCS = main.c daemon_utils.c file_monitor.c syscall_monitor.c process_analyzer.c \
       syscall_filter.c response.c behavioral_analysis.c entropy_analysis.c \
       process_relationship.c syscall_pattern.c hash_monitor.c whitelist.c activity_scorer.c \
       logger.c

OBJS = $(SRCS:.c=.o)
TARGET = ransomguard

HEADERS = *.h

PREFIX = /usr/local
BINDIR = $(PREFIX)/bin
CONFDIR = /etc
LOGDIR = /var/log/ransomguard
CONFFILE = ransomguard.conf
SYSTEMDDIR = /etc/systemd/system
SYSTEMDFILE = ransomguard.service

# Default build (production)
all: $(TARGET)

# Link final binary
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

install: $(TARGET)
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 $(TARGET) $(DESTDIR)$(BINDIR)
	install -d $(DESTDIR)$(CONFDIR)
	[ -f $(DESTDIR)$(CONFDIR)/$(CONFFILE) ] || install -m 644 ../config/$(CONFFILE) $(DESTDIR)$(CONFDIR)
	install -d $(DESTDIR)$(LOGDIR)
	chmod 750 $(DESTDIR)$(LOGDIR)
	@if [ -d $(DESTDIR)$(SYSTEMDDIR) ]; then \
		install -m 644 ../config/$(SYSTEMDFILE) $(DESTDIR)$(SYSTEMDDIR); \
		echo "Run 'systemctl daemon-reload' to update systemd"; \
	fi
	@echo "Installation complete!"
	@echo "Run 'systemctl enable --now ransomguard' to start the service automatically"

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(TARGET)
	rm -f $(DESTDIR)$(SYSTEMDDIR)/$(SYSTEMDFILE)
	@echo "Configuration files and logs were not removed."
	@echo "Remove manually if desired: $(DESTDIR)$(CONFDIR)/$(CONFFILE) and $(DESTDIR)$(LOGDIR)"

clean:
	rm -f $(OBJS) $(TARGET) *.core

test: $(TARGET)
	./$(TARGET) --watchdir=/tmp/test --no-daemon --verbose=2

unittest: $(TARGET)
	@echo "Running unit tests..."
	@if [ ! -d ../tests ]; then mkdir -p ../tests; fi
	$(CC) $(CFLAGS) -o ../tests/test_entropy ../tests/test_entropy.c entropy_analysis.c $(LDFLAGS)
	$(CC) $(CFLAGS) -o ../tests/test_syscall_filter ../tests/test_syscall_filter.c syscall_filter.c $(LDFLAGS)
	$(CC) $(CFLAGS) -o ../tests/test_hash_monitor ../tests/test_hash_monitor.c hash_monitor.c $(LDFLAGS)
	../tests/test_entropy
	../tests/test_syscall_filter
	../tests/test_hash_monitor

debug: CFLAGS += -DDEBUG -O0 -ggdb3 -fsanitize=address -fsanitize=undefined
debug: LDFLAGS += -fsanitize=address -fsanitize=undefined
debug: clean $(TARGET)

memcheck: $(TARGET)
	valgrind --leak-check=full --show-leak-kinds=all ./$(TARGET) --watchdir=/tmp/test --no-daemon --verbose=2

security-check:
	@echo "Running security checks..."
	cppcheck --enable=all --inconclusive --std=c11 *.c *.h
	flawfinder --minlevel=1 .
	@echo "Security check complete"

gen-service:
	@echo "[Unit]" > ../config/$(SYSTEMDFILE)
	@echo "Description=RansomGuard Ransomware Detection Service" >> ../config/$(SYSTEMDFILE)
	@echo "After=network.target" >> ../config/$(SYSTEMDFILE)
	@echo "" >> ../config/$(SYSTEMDFILE)
	@echo "[Service]" >> ../config/$(SYSTEMDFILE)
	@echo "Type=forking" >> ../config/$(SYSTEMDFILE)
	@echo "ExecStart=$(BINDIR)/$(TARGET) --daemon --pidfile=/var/run/$(TARGET).pid" >> ../config/$(SYSTEMDFILE)
	@echo "PIDFile=/var/run/$(TARGET).pid" >> ../config/$(SYSTEMDFILE)
	@echo "Restart=always" >> ../config/$(SYSTEMDFILE)
	@echo "RestartSec=5" >> ../config/$(SYSTEMDFILE)
	@echo "" >> ../config/$(SYSTEMDFILE)
	@echo "[Install]" >> ../config/$(SYSTEMDFILE)
	@echo "WantedBy=multi-user.target" >> ../config/$(SYSTEMDFILE)
	@echo "Generated service file: ../config/$(SYSTEMDFILE)"

test-env:
	@echo "Creating test environment in /tmp/test"
	@mkdir -p /tmp/test/normal /tmp/test/encrypted
	@for i in $$(seq 1 10); do \
		dd if=/dev/urandom of=/tmp/test/normal/file$$i.txt bs=1M count=1 2>/dev/null; \
	done
	@echo "Test environment created"

simulate-ransomware:
	@if [ ! -d /tmp/test ]; then make test-env; fi
	@echo "Simulating ransomware behavior in /tmp/test (safe test)"
	@for i in $$(seq 1 10); do \
		openssl enc -aes-256-cbc -salt -pbkdf2 -in /tmp/test/normal/file$$i.txt -out /tmp/test/encrypted/file$$i.enc -pass pass:ransomtest; \
	done
	@echo "Simulation complete - check if RansomGuard detected the activity"

coverage:
	$(MAKE) clean
	$(MAKE) CFLAGS="$(CFLAGS) --coverage" LDFLAGS="$(LDFLAGS) --coverage"
	./$(TARGET) --watchdir=/tmp/test --no-daemon --timeout=20
	gcov -b *.c
	lcov --capture --directory . --output-file coverage.info
	genhtml coverage.info --output-directory coverage_report
	@echo "Coverage report generated in coverage_report/index.html"

.PHONY: all install uninstall clean test unittest debug memcheck security-check gen-service test-env simulate-ransomware coverage