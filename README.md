# RansomGuard

RansomGuard is a lightweight daemon for detecting and preventing ransomware activity on Linux systems. It monitors system calls, file activity, and process behavior to identify potential ransomware operations and take preventive action.

## Installation

### Dependencies

- Linux kernel 3.5+
- libseccomp (for syscall filtering)
- GCC and Make

### Building from source

```bash
# Install dependencies
sudo apt install build-essential libseccomp-dev

# Build the project
make

# Install (optional)
sudo make install
```

### Usage
```bash
# Start monitoring your home directory as a daemon
sudo ransomguard --daemon --watchdir=/home/user

# Monitor a specific directory
sudo ransomguard --daemon --watchdir=/path/to/important/files

# Monitor a specific process
sudo ransomguard --daemon --monitor-pid=1234
```



### RansomGuard - Ransomware Detection daemon
```sh
Usage:
  ransomguard [OPTIONS]

Options:
  -d, --daemon              Run as daemon
  -p, --pidfile=FILE        PID file path (default: /var/run/ransomguard.pid)
  -c, --config=FILE         Config file path (default: /etc/ransomguard.conf)
  -w, --watchdir=DIR        Directory to monitor (default: /home)
  -m, --monitor-pid=PID     Specific process PID 
  -h, --help                Display this help and exit
```

### Configuration
The default configuration file is located at /etc/ransomguard.conf. You can specify a different path using the --config option.

Example configuration:

```bash
# RansomGuard configuration

# Directories to monitor (comma-separated)
watch_dirs=/home,/var/www

# File extensions to monitor closely (comma-separated)
sensitive_extensions=doc,docx,xls,xlsx,pdf,jpg,png

# Thresholds for detection
file_write_threshold=50
file_rename_threshold=20
file_delete_threshold=10

# Response options
enable_process_termination=true
enable_file_protection=true
```

### Contribution
Contributions are welcome! Please feel free to submit a Pull Request.


