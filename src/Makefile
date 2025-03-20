# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -Werror -g -O2 -D_GNU_SOURCE -fstack-protector-strong
LDFLAGS = -lseccomp -lpthread -lcrypto -lm -lrt

# Directories
SRC_DIR = .
OBJ_DIR = obj
BIN_DIR = bin

# Sources and objects
SRCS = $(wildcard $(SRC_DIR)/*.c)
OBJS = $(SRCS:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)
TARGET = $(BIN_DIR)/ransomguard

# Headers
HEADERS = $(wildcard *.h)

# Install Paths
PREFIX = /usr/local
BINDIR = $(PREFIX)/bin
CONFDIR = /etc
LOGDIR = /var/log/ransomguard
CONFFILE = ransomguard.conf
SYSTEMDDIR = /etc/systemd/system
SYSTEMDFILE = ransomguard.service

# Ensure object and binary directories exist
$(shell mkdir -p $(OBJ_DIR) $(BIN_DIR))

# Default target
all: $(TARGET)

# Link final binary
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)

# Compile each source file into object files
$(OBJ_DIR)/%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

# Install binary, config, logs, and service file
install: $(TARGET)
	install -d $(DESTDIR)$(BINDIR) $(DESTDIR)$(CONFDIR) $(DESTDIR)$(LOGDIR)
	install -m 755 $(TARGET) $(DESTDIR)$(BINDIR)
	[ -f $(DESTDIR)$(CONFDIR)/$(CONFFILE) ] || install -m 644 ../config/$(CONFFILE) $(DESTDIR)$(CONFDIR)
	chmod 750 $(DESTDIR)$(LOGDIR)
	if [ -d $(DESTDIR)$(SYSTEMDDIR) ]; then \
		install -m 644 ../config/$(SYSTEMDFILE) $(DESTDIR)$(SYSTEMDDIR); \
		echo "Run 'systemctl daemon-reload' to update systemd"; \
	fi
	@echo "Installation complete!"

# Uninstall procedure
uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(TARGET)
	rm -f $(DESTDIR)$(SYSTEMDDIR)/$(SYSTEMDFILE)
	@echo "Configuration files and logs were not removed. Remove manually if needed."

# Clean compiled objects and binary
clean:
	rm -f $(OBJ_DIR)/*.o $(TARGET)

# Debug build
debug: CFLAGS += -DDEBUG -O0 -ggdb3 -fsanitize=address -fsanitize=undefined
debug: LDFLAGS += -fsanitize=address -fsanitize=undefined
debug: clean $(TARGET)

# Run memory check using Valgrind
memcheck: $(TARGET)
	valgrind --leak-check=full --show-leak-kinds=all ./$(TARGET) --watchdir=/tmp/test --no-daemon --verbose=2

# Generate coverage report
coverage:
	$(MAKE) clean
	$(MAKE) CFLAGS="$(CFLAGS) --coverage" LDFLAGS="$(LDFLAGS) --coverage"
	./$(TARGET) --watchdir=/tmp/test --no-daemon --timeout=20
	gcov -b $(SRC_DIR)/*.c
	lcov --capture --directory . --output-file coverage.info
	genhtml coverage.info --output-directory coverage_report
	@echo "Coverage report generated in coverage_report/index.html"

# Test execution
test: $(TARGET)
	./$(TARGET) --watchdir=/tmp/test --no-daemon --verbose=2

# Unit test execution
unittest: $(TARGET)
	@echo "Running unit tests..."
	$(CC) $(CFLAGS) -o ../tests/test_entropy ../tests/test_entropy.c $(SRC_DIR)/entropy_analysis.c $(LDFLAGS)
	$(CC) $(CFLAGS) -o ../tests/test_syscall_filter ../tests/test_syscall_filter.c $(SRC_DIR)/syscall_filter.c $(LDFLAGS)
	$(CC) $(CFLAGS) -o ../tests/test_hash_monitor ../tests/test_hash_monitor.c $(SRC_DIR)/hash_monitor.c $(LDFLAGS)
	../tests/test_entropy
	../tests/test_syscall_filter
	../tests/test_hash_monitor

# Create test environment
test-env:
	@mkdir -p /tmp/test/normal /tmp/test/encrypted
	@for i in $$(seq 1 10); do \
		dd if=/dev/urandom of=/tmp/test/normal/file$$i.txt bs=1M count=1; \
	done
	@echo "Test environment created."

# Simulate ransomware activity for testing
simulate-ransomware:
	@if [ ! -d /tmp/test ]; then make test-env; fi
	@for i in $$(seq 1 10); do \
		openssl enc -aes-256-cbc -salt -pbkdf2 -in /tmp/test/normal/file$$i.txt -out /tmp/test/encrypted/file$$i.enc -pass pass:ransomtest; \
	done
	@echo "Simulation complete."

.PHONY: all install uninstall clean debug memcheck coverage test unittest test-env simulate-ransomware
