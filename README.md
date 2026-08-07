# MessageU – End-to-End Encrypted Messaging

MessageU is a client-server messaging system that demonstrates binary network communication and end-to-end encryption.

The server is implemented in Python, while the command-line client is implemented in C++.

## Features

- Client-server communication over TCP
- Binary communication protocol using little-endian encoding
- User registration with UUID identifiers
- Retrieval of registered users
- Public-key exchange between clients
- Offline message storage and retrieval
- End-to-end encrypted text messaging
- Multithreaded Python server
- Defensive validation of request and payload sizes
- Object-oriented C++ client architecture

## Encryption

MessageU uses:

- RSA-1024 with OAEP-SHA for transferring symmetric keys
- AES-128 in CBC mode for encrypting text messages
- Crypto++ for cryptographic operations on the C++ client

The server stores and forwards encrypted messages but does not decrypt their contents.

## Architecture

```text
C++ Client A
     |
     | Encrypted message
     v
Python Server
     |
     | Stored and forwarded ciphertext
     v
C++ Client B
```

The Python server manages registered users, public keys, and pending messages.

Encryption and decryption are performed only by the clients.

## Project Structure

```text
MessageU-End-to-End-Messaging/
├── src/
│   ├── client/
│   │   └── client.cpp
│   └── server/
│       └── server.py
├── README.md
└── .gitignore
```

## Technologies

### Client

- C++
- Boost.Asio
- Crypto++
- TCP sockets
- Object-Oriented Programming

### Server

- Python 3
- TCP sockets
- Multithreading
- `struct` binary packing
- In-memory data storage

## Configuration

### Server

Create a file named `myport.info` in the server's working directory:

```text
1357
```

If the file is missing, the server uses port `1357`.

### Client

Create a file named `server.info` in the client's working directory:

```text
127.0.0.1:1357
```

The client creates `my.info` after registration.

This file contains the username, UUID, and private key and must never be committed to GitHub.

## Running the Project

### Start the server

From the server directory, run:

```bash
python server.py
```

### Build and start the client

1. Configure Boost.Asio and Crypto++ in the C++ build environment.
2. Build `client.cpp`.
3. Create the `server.info` configuration file in the client's working directory.
4. Run the compiled client.
5. Register a new user using option `110`.

At least two separate client instances are required to exchange encrypted messages.

## Client Commands

```text
110) Register
120) Request for clients list
130) Request for public key
140) Request for waiting messages
150) Send a text message
151) Send a request for symmetric key
152) Send your symmetric key
0) Exit client
```

## Protocol

The binary protocol supports:

- Registration
- Client-list retrieval
- Public-key retrieval
- Message transmission
- Pending-message retrieval

All numerical fields are encoded in little-endian byte order.

### Request Codes

| Code | Operation |
|---:|---|
| 700 | Register |
| 701 | Request clients list |
| 702 | Request public key |
| 703 | Send message |
| 704 | Pull pending messages |

### Response Codes

| Code | Meaning |
|---:|---|
| 2100 | Registration succeeded |
| 2101 | Clients list |
| 2102 | Public key |
| 2103 | Message stored |
| 2104 | Pending messages |
| 9000 | General error |

## Message Flow

1. A client registers and receives a UUID.
2. A client requests another user's public key.
3. A symmetric AES key is generated.
4. The symmetric key is encrypted using the recipient's RSA public key.
5. The encrypted key is sent through the server.
6. Text messages are encrypted using AES.
7. The server stores and forwards ciphertext without decrypting it.
8. The recipient pulls pending messages and decrypts them locally.

## Security Notice

This project was developed as an educational implementation of encrypted client-server communication.

It should not be used as a production messaging system without:

- Authenticated encryption
- Random and unique initialization vectors
- Secure public-key verification
- Protection against replay attacks
- Stronger identity authentication
- Persistent and secure server-side storage
- Additional input validation and rate limiting

## Privacy

The following runtime files are excluded from Git:

- `my.info`
- `server.info`
- `myport.info`
- Build outputs
- Executable files
- Local database files
- IDE-generated files
