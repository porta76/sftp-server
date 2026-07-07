# Simple SFTP Server (Python)

A lightweight SFTP server built with [Paramiko](https://www.paramiko.org/).

## Features

- Password-based authentication
- Per-user home directories (chroot)
- Auto-generated RSA host key
- Multi-threaded — handles multiple clients simultaneously
- Configurable via `config.py`

## Project Structure

```
sftp-server/
├── env/                # Python virtual environment
├── sftp-server/
│   ├── sftp_server.py  # Main server script
│   ├── config.py       # Server configuration (users, port, paths)
│   ├── requirements.txt # Python dependencies
│   └── README.md       # This file
```

## Quick Start

### 1. Activate the virtual environment

The project includes a virtual environment at `../env`. Activate it first:

**Windows (PowerShell):**

```powershell
..\env\Scripts\Activate.ps1
```

**Windows (CMD):**

```cmd
..\env\Scripts\activate.bat
```

**Linux / macOS:**

```bash
source ../env/bin/activate
```

### 2. Install dependencies (into the venv)

```bash
pip install -r requirements.txt
```

### 3. Create user directories

```powershell
New-Item -ItemType Directory -Force -Path sftp_root\admin, sftp_root\user1 | Out-Null
```

### 4. Run the server

```bash
python sftp_server.py
```

On first run, an RSA host key (`host_key_rsa`) is generated automatically.

### 4. Connect with an SFTP client

```bash
sftp -P 2222 admin@localhost
# Password: admin123
```

Or use FileZilla / WinSCP:

| Field    | Value             |
| -------- | ----------------- |
| Host     | `localhost`       |
| Port     | `2222`            |
| Protocol | `SFTP`            |
| Username | `admin`           |
| Password | `admin123`        |

## Configuration

Edit `config.py` to change:

- **`HOST` / `PORT`** — bind address and port
- **`USERS`** — username → password + home directory mapping
- **`HOST_KEY_PATH`** — path to the SSH host key
- **`LOG_FILE` / `LOG_LEVEL`** — logging settings

### Adding a new user

```python
USERS = {
    "admin": {
        "password": "admin123",
        "home_dir": "./sftp_root/admin",
    },
    "newuser": {
        "password": "secret",
        "home_dir": "./sftp_root/newuser",
    },
}
```

Then create the directory:

```bash
mkdir -p sftp_root/newuser
```

## Security Notes

- Change default passwords before deploying.
- Use port `22` only if the process has sufficient privileges (or run as root/admin).
- For production, consider using public-key authentication instead of passwords.
- The host key is generated on first run and saved to `host_key_rsa`. Keep it persistent across restarts.
