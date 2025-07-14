# Multithreaded Encrypted File Server & Client
<img width="360" height="500" alt="image" src="https://github.com/user-attachments/assets/e18c69e3-5904-4317-960a-9128f9dcba82" />

## what is this?

I want to make my own cloud storage essentially via an encrypted file server on some piece of hardware that i hook up with tailscale. (I'd rather not expose my home network to the internet thank you very much xd)

## how it works

Authentication is done via an sqlite3 database on the server side. Once authenticated, the user can do two actions. First is to encrypt and write a file to the server's file system, second is to decrypt and read a file from the server's file system. Encrypted files will be written to `MEF_S/<username>` directory on the server. The decrypted files will be written to the current working directory ./client program was executed in.

I used the libsodium for the cryptography and the standard library for the rest.

The underlying network protocol is TCP mainly to ensure packets arrive in order, encrypted chunks arriving in sequence is obviously important haha.

As you can guess from the directory naming, this server client model supports multiple clients reading and writing to the file system.


## dependencies:

Ubuntu/Ubuntu based (sorry if these pkgs are not on debian, i don't have a debian system TwT):
```
sudo apt install sqlite3 libsqlite3-dev libsodium-dev cmake build-essential
```

Fedora (what i'm using rn):
```
sudo dnf install sqlite-devel libsodium-devel libsodium-devel make cmake
```

## building

```cd build
cmake ..
make
```
## usage

terminal 1
```./server```

terminal 2
```./client```

testing credentials:

username: `henry`
password: `swabber`


username: `bungie`
password: `gourd`

Don't ask why I picked the names, for some reason I was thinking of superman then shortly after, cotton swabs. As for the other name, I don't even know xd

Follow the prompts given on client side and quit server by pressing `q` and `enter` when done :)

## demo
[![Single Client](https://img.youtube.com/vi/6Q8EOyWfPSA/0.jpg)](https://www.youtube.com/watch?v=6Q8EOyWfPSA)
