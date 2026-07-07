"""Simple SFTP server using Paramiko.

Usage:
    python sftp_server.py

The server listens on the host/port defined in config.py and authenticates
users defined in the USERS dictionary. Files are served from the directory
specified for each user.
"""

import logging
import os
import socket
import threading

import paramiko

from config import HOST, PORT, HOST_KEY_PATH, USERS, LOG_FILE, LOG_LEVEL


def setup_logging():
    logging.basicConfig(
        level=getattr(logging, LOG_LEVEL, logging.INFO),
        format="%(asctime)s [%(levelname)s] %(threadName)s: %(message)s",
        handlers=[
            logging.FileHandler(LOG_FILE),
            logging.StreamHandler(),
        ],
    )


def load_host_key():
    """Load or generate an RSA host key for the SSH server."""
    if os.path.exists(HOST_KEY_PATH):
        host_key = paramiko.RSAKey(filename=HOST_KEY_PATH)
        logging.info("Loaded host key from %s", HOST_KEY_PATH)
    else:
        logging.info("Generating new RSA host key...")
        host_key = paramiko.RSAKey.generate(bits=2048)
        host_key.write_private_key_file(HOST_KEY_PATH)
        logging.info("Saved host key to %s", HOST_KEY_PATH)
    return host_key


class SimpleSFTPServerInterface(paramiko.SFTPServerInterface):
    """SFTP server interface that serves files from a chrooted home directory."""

    def __init__(self, server, *args, **kwargs):
        super().__init__(server, *args, **kwargs)
        # Store the server reference (base class doesn't save it)
        self._server = server
        # The home directory is set by SimpleSFTPServer.start_subsystem()
        # before any SFTP operations are processed. Default to CWD as fallback.
        self._home_dir = getattr(server, "_home_dir", os.getcwd())

    def session_started(self):
        # The home directory was already set on us by SimpleSFTPServer.start_subsystem()
        logging.info("SFTP session started, home=%s", self._home_dir)

    def _real_path(self, path):
        """Resolve a client-relative path to a real filesystem path, confined to home."""
        # Strip leading slashes so the path is relative to the home dir
        clean = path.lstrip("/")
        real = os.path.realpath(os.path.join(self._home_dir, clean))
        # Prevent escaping the home directory via ../
        home_real = os.path.realpath(self._home_dir)
        if not (real == home_real or real.startswith(home_real + os.sep)):
            real = home_real
        return real

    def list_folder(self, path):
        real = self._real_path(path)
        try:
            entries = []
            for name in os.listdir(real):
                full = os.path.join(real, name)
                attr = paramiko.SFTPAttributes.from_stat(os.stat(full))
                attr.filename = name
                entries.append(attr)
            return entries
        except OSError as e:
            return paramiko.SFTPServer.convert_errno(e.errno)

    def open(self, path, flags, attr):
        real = self._real_path(path)
        try:
            flags |= getattr(os, "O_BINARY", 0)
            fd = os.open(real, flags)
            handle = paramiko.SFTPHandle(flags)
            handle.filename = real
            # Determine the Python file mode based on the open flags
            if flags & os.O_WRONLY:
                mode = "wb"
            elif flags & os.O_RDWR:
                mode = "r+b"
            else:
                mode = "rb"
            f = os.fdopen(fd, mode)
            handle.readfile = f
            handle.writefile = f if (flags & (os.O_WRONLY | os.O_RDWR)) else None
            return handle
        except OSError as e:
            return paramiko.SFTPServer.convert_errno(e.errno)

    def stat(self, path):
        real = self._real_path(path)
        try:
            return paramiko.SFTPAttributes.from_stat(os.stat(real))
        except OSError as e:
            return paramiko.SFTPServer.convert_errno(e.errno)

    def lstat(self, path):
        real = self._real_path(path)
        try:
            return paramiko.SFTPAttributes.from_stat(os.lstat(real))
        except OSError as e:
            return paramiko.SFTPServer.convert_errno(e.errno)

    def remove(self, path):
        real = self._real_path(path)
        try:
            os.remove(real)
            return paramiko.SFTP_OK
        except OSError as e:
            return paramiko.SFTPServer.convert_errno(e.errno)

    def mkdir(self, path, attr):
        real = self._real_path(path)
        try:
            os.mkdir(real)
            return paramiko.SFTP_OK
        except OSError as e:
            return paramiko.SFTPServer.convert_errno(e.errno)

    def rmdir(self, path):
        real = self._real_path(path)
        try:
            os.rmdir(real)
            return paramiko.SFTP_OK
        except OSError as e:
            return paramiko.SFTPServer.convert_errno(e.errno)

    def rename(self, oldpath, newpath):
        old_real = self._real_path(oldpath)
        new_real = self._real_path(newpath)
        try:
            os.rename(old_real, new_real)
            return paramiko.SFTP_OK
        except OSError as e:
            return paramiko.SFTPServer.convert_errno(e.errno)

    def realpath(self, path):
        return path.lstrip("/")

    def chattr(self, path, attr):
        real = self._real_path(path)
        try:
            if attr.st_mode is not None:
                os.chmod(real, attr.st_mode)
            return paramiko.SFTP_OK
        except OSError as e:
            return paramiko.SFTPServer.convert_errno(e.errno)


class SimpleSFTPServer(paramiko.SFTPServer):
    """SFTPServer that resolves the home directory from the authenticated user."""

    def start_subsystem(self, name, transport, channel):
        username = transport.get_username()
        home_dir = USERS.get(username, {}).get("home_dir", os.getcwd())
        self._home_dir = os.path.abspath(home_dir)
        # Propagate the home directory to the SFTPServerInterface instance
        self.server._home_dir = self._home_dir
        logging.info("SFTP subsystem started for '%s', home=%s", username, self._home_dir)
        super().start_subsystem(name, transport, channel)


class SimpleSSHServer(paramiko.ServerInterface):
    """SSH server interface with password authentication."""

    def check_auth_password(self, username, password):
        user = USERS.get(username)
        if user and user["password"] == password:
            logging.info("User '%s' authenticated successfully", username)
            return paramiko.AUTH_SUCCESSFUL
        logging.warning("Authentication failed for user '%s'", username)
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED


def handle_client(client_sock, addr, host_key):
    """Handle a single SSH/SFTP client connection."""
    transport = None
    try:
        transport = paramiko.Transport(client_sock)
        transport.add_server_key(host_key)

        # Register the SFTP subsystem handler so paramiko manages it
        transport.set_subsystem_handler("sftp", SimpleSFTPServer, SimpleSFTPServerInterface)

        server = SimpleSSHServer()
        transport.start_server(server=server)

        # Block until the transport closes (subsystem runs in a paramiko thread)
        transport.join()

    except paramiko.SSHException as exc:
        logging.error("SSH error from %s: %s", addr, exc)
    except Exception as exc:
        logging.error("Error handling client %s: %s", addr, exc)
    finally:
        if transport is not None:
            transport.close()
        client_sock.close()
        logging.info("Connection closed from %s", addr)


def main():
    setup_logging()
    host_key = load_host_key()

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((HOST, PORT))
    server_sock.listen(100)

    logging.info("SFTP server listening on %s:%d", HOST, PORT)
    logging.info("Configured users: %s", ", ".join(USERS.keys()))

    try:
        while True:
            client_sock, addr = server_sock.accept()
            logging.info("Incoming connection from %s", addr)
            thread = threading.Thread(
                target=handle_client,
                args=(client_sock, addr, host_key),
                daemon=True,
            )
            thread.start()
    except KeyboardInterrupt:
        logging.info("Server shutting down...")
    finally:
        server_sock.close()


if __name__ == "__main__":
    main()