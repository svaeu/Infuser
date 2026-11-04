# Infuser

Encrypted, client-server group messaging with a command-line interface, written in Java.

Users connect to a self-hosted server, register a device-bound identity, join channels (rooms) and chat. All traffic is encrypted in transit, and chat messages are additionally encrypted with a per-channel key.

---

## Table of contents

- [Features](#features)
- [How it works](#how-it-works)
- [Project structure](#project-structure)
- [Requirements](#requirements)
- [Build](#build)
- [Setup and run](#setup-and-run)
  - [1. Configure the server](#1-configure-the-server)
  - [2. Start the server](#2-start-the-server)
  - [3. Create channels](#3-create-channels)
  - [4. Run the client](#4-run-the-client)
- [Client commands](#client-commands)
- [Server administration](#server-administration)
- [Configuration reference](#configuration-reference)
- [Files created at runtime](#files-created-at-runtime)
- [Troubleshooting](#troubleshooting)
- [Known limitations](#known-limitations)
- [License](#license)

---

## Features

- **Encrypted sessions**: ECDHE (P-256) key exchange, session keys derived with HKDF-SHA256, AES-256-GCM for packet encryption.
- **Server identity verification**: the server signs its ephemeral key with a 4096-bit RSA identity key; clients pin the server's public key on first use (TOFU).
- **Group channels** with a member limit, plus `PRIVATE` (permission-gated) and `LOCKED` (read-only) channel states.
- **Per-channel keys**: chat payloads are encrypted with a key shared by the channel's members.
- **Device-bound login**: the auth token is stored encrypted on disk and protected by a password you choose.
- **IP allow/deny lists** (whitelist mode and blacklist) stored in the database.
- **Zero-setup storage**: embedded SQLite, no external database needed.
- **Modular design**: client, server and shared packet/crypto code are separate Maven modules.

## How it works

```
┌──────────┐   1. TOFU: request server public key (first run only)    ┌──────────┐
│          │ ───────────────────────────────────────────────────────▶ │          │
│  Client  │   2. ECDHE handshake, server signs its EC key (RSA)       │  Server  │
│  (CLI)   │ ◀──────────────────────────────────────────────────────▶ │  (TCP)   │
│          │   3. Register / log in with token (AES-GCM session)       │ + SQLite │
│          │   4. Join channel, receive channel key from a member      │          │
│          │   5. Chat: payload encrypted with the channel key         │          │
└──────────┘ ───────────────────────────────────────────────────────▶ └──────────┘
```

1. **First contact**: if the client has no `server_fingerprint.key` in its working directory, it asks the server for its public key and trusts it from then on (Trust On First Use).
2. **Handshake**: both sides run an ephemeral ECDH exchange. The server signs its ephemeral public key with its RSA identity key, and the client verifies the signature against the pinned key. An AES-256 session key is derived with HKDF.
3. **Registration / login**: on first run you pick a username and the server issues a random token. The client stores it encrypted (`.enc_auth_token`) using a key derived from your token password and your OS user/OS/architecture. On later runs you enter the password and the client logs in with the token.
4. **Channels**: when you join a channel, an existing member provides the channel key (or, for an empty channel, a fresh key exchange is started). Chat messages are encrypted with that channel key before they are sent.

> **Security note:** the server relays channel keys between members (re-wrapped under each member's session key), so it is part of the trust boundary. Only run a server you trust.

## Project structure

```
Infuser/
├── pom.xml              # Parent POM (Java 22, modules below)
├── client/              # CLI client (JLine, BouncyCastle)
├── server/              # TCP server (SQLite, SnakeYAML, BouncyCastle)
└── shared-packets/      # Packet definitions, stream wrappers, crypto utilities
```

| Module | Artifact | Purpose |
|---|---|---|
| `shared-packets` | `shared-packets` | `Packet` types, packet (de)serialisation, ECDHE / RSA helpers |
| `server` | `infuser-server` | Accepts connections, authenticates users, manages channels, persists data |
| `client` | `infuser-client` | Terminal chat client |

## Requirements

- **JDK 22** or newer (the project is compiled with `maven.compiler.source/target = 22`)
- **Apache Maven 3.9+**
- **Git**
- *(optional)* the `sqlite3` command-line tool, or any SQLite GUI (e.g. DB Browser for SQLite), for creating channels and managing users
- A terminal that supports ANSI colours (the client uses JLine)

Check your versions:

```bash
java -version
mvn -version
```

## Build

```bash
git clone https://github.com/svaeu/Infuser.git
cd Infuser
mvn clean install -DskipTests
```

This builds all three modules and installs them into your local Maven repository (the server run command below relies on this). The client is packaged as a self-contained ("shaded") jar:

```
client/target/infuser-client-x1.0.0.jar
```

## Setup and run

All server files (`config.yml`, the database, keys, logs) are created **relative to the directory you start the server from**. Pick a directory and use it consistently. The examples below use the repository root.

### 1. Configure the server

The server reads `config.yml` from its working directory on startup. No default file is shipped, so create one:

```yaml
# config.yml
server:
  port: 1207            # TCP port to listen on
  isWhitelisted: false  # true = only IPs whitelisted in the database may connect
  database:
    path: inf_dev.db3   # SQLite file; created automatically if missing
```

### 2. Start the server

```bash
mvn -q -pl server exec:java -Dexec.mainClass=com.github.svaeu.infuser.server.ServerMain
```

On the first start the server:

- creates the SQLite database and its tables,
- generates a 4096-bit RSA identity key pair in `id_keys/` (this can take a few seconds),
- creates `server_logs/` and writes a log file for the session,
- starts listening on the configured port (default `1207`).

Stop it with `Ctrl+C`.

> Back up `id_keys/` and keep `id_keys/private_signing.key` private. If you lose or regenerate the identity key, every client that pinned the old public key will refuse to connect until its `server_fingerprint.key` is deleted.

### 3. Create channels

Channels live in the `room_data` table and are loaded when the server starts. There is currently no in-app command to create them, so insert them with SQL (after the first start has created the tables):

```bash
sqlite3 inf_dev.db3 <<'SQL'
INSERT INTO room_data (title, threshold, states) VALUES ('general', 50, '');
INSERT INTO room_data (title, threshold, states) VALUES ('staff',    5, 'PRIVATE');
SQL
```

| Column | Meaning |
|---|---|
| `title` | Channel name (case-insensitive when joining). Titles starting with `*` are ignored. |
| `threshold` | Maximum number of simultaneous members. |
| `states` | Comma-separated list of `HIDDEN`, `PRIVATE`, `LOCKED`, or empty. |

Restart the server so it picks up the new channels.

### 4. Run the client

```bash
java -cp client/target/infuser-client-x1.0.0.jar \
  com.github.svaeu.infuser.client.ClientMain <server-ip> <port> --nogui
```

Example for a local server:

```bash
java -cp client/target/infuser-client-x1.0.0.jar \
  com.github.svaeu.infuser.client.ClientMain 127.0.0.1 1207 --nogui
```

> `--nogui` is required: only the command-line interface is implemented at the moment.

**First run**

1. The client trusts and stores the server's public key as `server_fingerprint.key` (TOFU).
2. It asks you to **choose a username** (3-32 characters: letters, digits, `_` or `-`; stored lowercase).
3. The server issues a token and you are asked to **set a password for the token**. The token is saved, encrypted, as `.enc_auth_token`.

**Later runs**: enter the token password to log in.

> Run the client from the same directory every time. `server_fingerprint.key` and `.enc_auth_token` are looked up in the working directory. The token is bound to your OS user, OS and architecture, so it cannot be copied to another machine or account (re-register there instead).

### Quick start (everything on one machine)

```bash
# terminal 1: build, configure, start the server
mvn clean install -DskipTests
printf 'server:\n  port: 1207\n  isWhitelisted: false\n  database:\n    path: inf_dev.db3\n' > config.yml
mvn -q -pl server exec:java -Dexec.mainClass=com.github.svaeu.infuser.server.ServerMain
#   Ctrl+C once it is running, add a channel, then start it again:
sqlite3 inf_dev.db3 "INSERT INTO room_data (title, threshold, states) VALUES ('general', 50, '');"
mvn -q -pl server exec:java -Dexec.mainClass=com.github.svaeu.infuser.server.ServerMain

# terminal 2 (and 3, with a different account/directory): run a client
java -cp client/target/infuser-client-x1.0.0.jar \
  com.github.svaeu.infuser.client.ClientMain 127.0.0.1 1207 --nogui
# then:  .list   →   .join general   →   type a message
```

## Client commands

Commands start with a dot. Anything else you type is sent as a message to your current channel.

| Command | Description |
|---|---|
| `.list` | List available channels with member counts |
| `.join <roomID>` | Join the channel with the given name |

You must join a channel before you can chat. The prompt shows your current channel and its occupancy, e.g. `[general] (2/50) | ~alice >`.

## Server administration

Administration is done directly in the SQLite database (e.g. `sqlite3 inf_dev.db3`).

**Channel states**

| State | Effect |
|---|---|
| `PRIVATE` | Only users holding the permission `<channel title>.access` can join |
| `LOCKED` | Messages sent to the channel are not delivered (read-only) |
| `HIDDEN` | Reserved; not enforced by the server yet |

**Grant a user access to a private channel** (permissions are a comma-separated list, read at login):

```sql
UPDATE user_data SET permissions = 'staff.access' WHERE username = 'alice';
-- multiple permissions: 'staff.access,ops.access'
```

**IP whitelist / blacklist** (loaded at startup):

```sql
INSERT OR REPLACE INTO ip_access (ip_address, status) VALUES ('203.0.113.7', 'blacklisted');
INSERT OR REPLACE INTO ip_access (ip_address, status) VALUES ('127.0.0.1',   'whitelisted');
```

Blacklisted IPs are always dropped. With `isWhitelisted: true`, **only** whitelisted IPs may connect, so whitelist `127.0.0.1` before testing locally.

**Database tables**

| Table | Columns |
|---|---|
| `user_data` | `username` (PK), `permissions`, `token` |
| `room_data` | `title` (PK), `threshold`, `states` |
| `ip_access` | `ip_address` (PK), `status` (`whitelisted` / `blacklisted`) |

## Configuration reference

`config.yml` (server working directory):

| Key | Type | Default | Description |
|---|---|---|---|
| `server.port` | int | `1207` | TCP port the server listens on |
| `server.isWhitelisted` | bool | `false` | Restrict connections to whitelisted IPs |
| `server.database.path` | string | *(empty)* | Path to the SQLite file. **Set this**: the empty default is not usable |

Client arguments:

```
<ip> <port> [--nogui]
```

## Files created at runtime

All of these are git-ignored.

| File / directory | Created by | Contents |
|---|---|---|
| `config.yml` | you | Server configuration |
| `inf_dev.db3` (name set in config) | server | Users, channels, IP lists |
| `id_keys/` | server | RSA identity key pair (`server_fingerprint.key`, `private_signing.key`) |
| `server_logs/` | server | One log file per server session |
| `server_fingerprint.key` | client | Pinned server public key |
| `.enc_auth_token` | client | Encrypted login token |

## Troubleshooting

**`default server configuration file could not be loaded`**: `config.yml` is missing from the directory you started the server in. Create it as shown in [Configure the server](#1-configure-the-server).

**`Could not find or load main class ...client.test` when using `java -jar`**: the client's POM points the jar manifest at a class that does not exist. Launch with `-cp ... ClientMain` as shown above, or change `<mainClass>` in `client/pom.xml` (both the shade and jar plugin blocks) and `client/src/main/resources/META-INF/MANIFEST.MF` to `com.github.svaeu.infuser.client.ClientMain`.

**Client prints a usage message or crashes right after start**: pass `--nogui` as the third argument.

**`release version 22 not supported` / `invalid target release: 22`**: you are building with an older JDK. Install JDK 22+ and make sure `JAVA_HOME` points to it.

**`Blocked mirror for repositories` during the build**: Maven 3.8.1+ refuses plain-HTTP repositories. In `server/pom.xml`, change the `Sonatype-public` URL to `https://` or remove the `<repositories>` block (SnakeYAML is available from Maven Central).

**`Could not find artifact ...shared-packets:jar:x1.0.0` when starting the server**: run `mvn clean install -DskipTests` from the repository root first so the shared module is installed locally.

**Client refuses to connect after the server was reinstalled / keys regenerated**: the pinned key no longer matches. Delete `server_fingerprint.key` on the client to trust the new key (only do this if you expected the change).

**`Token identity verification failed`**: wrong token password, or the token file was created under a different OS user, OS or architecture. Delete `.enc_auth_token` and register again.

**`You're already logged in from another instance!`**: the same account is connected elsewhere. Disconnect that session first.

**New channel does not show up in `.list`**: channels are read at server startup. Restart the server.

## Known limitations

- Only the command-line interface is implemented; the GUI mode is a placeholder.
- Channels, permissions and IP lists are managed through SQL; there are no in-app admin commands yet.
- The server does not ship a default `config.yml`.
- The `HIDDEN` channel state is defined but not yet enforced.
- Text chat only; media upload is not implemented.

## License

Released under the [CC0 1.0 Universal](LICENSE) public domain dedication.
