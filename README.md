# Multithreaded Encrypted File Server & Client
<img width="1291" height="965" alt="image" src="https://github.com/user-attachments/assets/9b9c54f4-5633-4f68-91bc-a4b13e0eaa0d" />

---

## 📦 What Is This?


MEFSC is a C++ based encrypted file server/client system that allows multiple users to securely store and retrieve files over a local or remote network. It's meant to act as your own private cloud, hosted on hardware you own and ideally accessed via [Tailscale](https://tailscale.com/) or other VPN, because exposing your home network to the open internet is... no thanks 😅

### Features:

- Secure file upload/download via symmetric encryption
- User authentication via SQLite3
- File chunking and encryption with [libsodium](https://libsodium.gitbook.io/doc/)
- Multi-user access
- Tailscale compatibility for remote, secure connectivity

Encrypted files are stored on the server under per-user directories, and decrypted files are downloaded locally to the client’s working directory.

---

## 🔐 How It Works

### 🔑 Authentication
- Users authenticate with credentials stored in a local SQLite3 database on the server.
- After successful login, the client can:
  1. Encrypt and upload a file to the server
  2. Download and decrypt a file from the server

### 💾 Storage
- Server stores files encrypted at rest in:
```build/MEF_S/<username>/```

- Client writes decrypted files to its current working directory.

### 🌐 Networking
- Uses **TCP** sockets for reliable, in-order chunk transmission because encrypted chunk shuffling would make decryption impossible.
- Everything is encrypted client-side before transmission, and decrypted after download.

### 🔒 Cryptography
- Uses **libsodium** for encryption.
- Symmetric encryption is applied per session.
- Files are encrypted/decrypted in chunks for better scalability and memory efficiency.

---

## 🛠 Dependencies

### Ubuntu / Ubuntu-based:
```
sudo apt install sqlite3 libsqlite3-dev libsodium-dev cmake build-essential
```



### Fedora (my machine)
```
sudo dnf install sqlite-devel libsodium-devel make cmake
```

## 🏗 Building
```
cd build
cmake ..
make
```

`build/server` is the server binary.
`build/client_fs/client` is the client binary.

Execute them and follow the prompts :) it's that straight forward.


## demo
[![Single Client](https://img.youtube.com/vi/6Q8EOyWfPSA/0.jpg)](https://www.youtube.com/watch?v=6Q8EOyWfPSA)
