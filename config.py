"""Configuration for the SFTP server."""

# Network settings
HOST = "0.0.0.0"          # Listen on all interfaces
PORT = 2222               # SFTP port (22 requires admin privileges)

# Host key file path (auto-generated on first run)
HOST_KEY_PATH = "host_key_rsa"

# Logging
LOG_FILE = "sftp_server.log"
LOG_LEVEL = "INFO"

# User database
# Each user has a password and a home directory (chroot root for SFTP).
# Create these directories before starting the server.
USERS = {
    "admin": {
        "password": "admin123",
        "home_dir": "./sftp_root/admin",
    },
    "user1": {
        "password": "user1123",
        "home_dir": "./sftp_root/user1",
    },
}