# Multithreaded Encrypted File Server & Client
<img width="1291" height="965" alt="image" src="https://github.com/user-attachments/assets/9b9c54f4-5633-4f68-91bc-a4b13e0eaa0d" />

---

MEFSC is a C++ based encrypted file server/client system that allows multiple users to securely store and retrieve files over a local or remote network. It's meant to act as your own private cloud, hosted on hardware you own and ideally accessed via [Tailscale](https://tailscale.com/) or other VPN.

## Demo

[![Single Client Demonstration](https://img.youtube.com/vi/PG-KranoF8w/0.jpg)](https://youtu.be/PG-KranoF8w)

## Features

- Secure file upload/download via symmetric encryption
- User authentication via SQLite3
- File chunking and encryption with [libsodium](https://libsodium.gitbook.io/doc/)
- Multi-user access with thread pool for concurrent connections
- **Client TUI** with arrow-key menu (powered by [FTXUI](https://github.com/ArthurSonzogni/FTXUI))
- **Live server dashboard** with real-time connection tracking (ANSI in-place refresh)
- **Strongly-typed action enums** instead of raw integer constants
- Tailscale compatibility for remote, secure connectivity

Encrypted files are stored on the server under per-user directories, and decrypted files are downloaded locally to the client's working directory.

---

## How It Works

### Authentication
- Users authenticate with credentials stored in a local SQLite3 database on the server.
- After successful login, the client presents an interactive menu:
  1. Upload File (encrypt + send)
  2. Download File (receive + decrypt)
  3. List Files
  4. Delete File
  5. Quit

### Storage
- Server stores files encrypted at rest in:
```build/MEF_S/<username>/
```
- Client writes decrypted files to its current working directory.

### Networking
- Uses **TCP** sockets for reliable, in-order chunk transmission because encrypted chunk shuffling would make decryption impossible.
- Everything is encrypted client-side before transmission, and decrypted after download.
- Server uses a thread pool (configurable size) to handle concurrent clients.

### Cryptography
- Uses **libsodium** for all cryptographic operations.
- Key exchange via `crypto_kx` (Curve25519 + BLAKE2b).
- Session encryption via `crypto_aead_chacha20poly1305`.
- File encryption via `crypto_secretstream_xchacha20poly1305` (chunked streaming).
- Passwords hashed with `crypto_pwhash_str` (Argon2id).

---

## Dependencies

### Ubuntu / Ubuntu-based:
```
sudo apt install sqlite3 libsqlite3-dev libsodium-dev cmake build-essential
```

### Fedora
```
sudo dnf install sqlite-devel libsodium-devel cmake gcc-c++
```

FTXUI (v6.1.9) is fetched automatically by CMake via FetchContent — no manual install needed.

## Building

```sh
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
```

## Launching

### 1. Create a user (one-time setup)

```sh
cd build
./tests/gen_hash <password>        # prints a password hash
sqlite3 MEFSC_DB.db "CREATE TABLE users(username TEXT PRIMARY KEY, hashed_pswd TEXT);"
sqlite3 MEFSC_DB.db "INSERT INTO users VALUES('alice', '<paste-hash-here>');"
cd ..
```

### 2. Start the server

```sh
cd build && ./server
```

The server dashboard shows live metrics (uptime, total/live connections, active client FDs) updating in-place.

### 3. Start a client

```sh
./build/client_fs/client
```

Navigate the menu with **arrow keys**, select with **Enter**, or press **q** to quit.
