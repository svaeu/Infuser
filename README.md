# Infuser

Encrypted client-server group messaging in Java, with a command-line client.

> **Proof of concept.** Infuser exists to build and harden the encryption design (ECDHE key exchange, pinned server identity, per-channel keys) that its successor [vaulk-protocol](https://github.com/svaeu/vaulk-protocol) builds on. It is not production software: it has no admin UI, no media, and no GUI, and it has only been tested at the level described under [Tests](#tests).

---

## Table of contents

- [Quick start](#quick-start)
- [Requirements](#requirements)
- [How it works](#how-it-works)
- [Using the client](#using-the-client)
- [Server administration (optional)](#server-administration-optional)
- [Configuration reference](#configuration-reference)
- [Files created at runtime](#files-created-at-runtime)
- [Project structure](#project-structure)
- [Tests](#tests)
- [Security notes](#security-notes)
- [Scope](#scope)
- [Troubleshooting](#troubleshooting)
- [License](#license)

---

## Quick start

Everything below runs on one machine. You need a JDK and Maven (see [Requirements](#requirements)); nothing else has to be installed or configured by hand.

**1. Build**

```bash
git clone https://github.com/svaeu/Infuser.git
cd Infuser
mvn clean install -DskipTests
```

**2. Start the server** (terminal 1, from the repository root)

```bash
mvn -q -pl server exec:java -Dexec.mainClass=com.github.svaeu.infuser.server.ServerMain
```

On first start the server creates everything it needs: `config.yml` with defaults, the SQLite database, a 4096-bit RSA identity key pair in `id_keys/` (a few seconds), a log file in `server_logs/`, and a default channel called `general`. It then listens on port `1207`. Stop it with `Ctrl+C`.

**3. Start a client** (terminal 2)

```bash
java -jar client/target/infuser-client-x1.0.0.jar 127.0.0.1 1207
```

On the first run the client trusts and pins the server's key, asks you to **choose a username**, and asks you to **set a password** that protects your login token. Then:

```
.list              show channels
.join general      join one
hello everyone     anything without a leading dot is sent as a message
```

**4. Add a second user** (terminal 3)

The client keeps its pinned key and login token in the directory it is started from, so a second user needs a different directory:

```bash
mkdir -p ../bob && cd ../bob
java -jar ../Infuser/client/target/infuser-client-x1.0.0.jar 127.0.0.1 1207
```

---

## Requirements

- **JDK 22** or newer
- **Apache Maven 3.9+**
- **Git**
- A terminal that supports ANSI colours (the client uses JLine)
- *(optional)* the `sqlite3` command-line tool, only for [server administration](#server-administration-optional)

```bash
java -version
mvn -version
```

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
2. **Handshake**: both sides run an ephemeral ECDH (P-256) exchange. The server signs its ephemeral public key with its 4096-bit RSA identity key, and the client verifies the signature against the pinned key. An AES-256 session key is derived with HKDF-SHA256, and all packets are encrypted with AES-GCM.
3. **Registration / login**: on first run you pick a username and the server issues a random token. The client stores it encrypted (`.enc_auth_token`) using a key derived from your token password and your OS user, OS and architecture. On later runs you enter the password and the client logs in with the token.
4. **Channels**: when you join a channel, an existing member provides the channel key (or, for an empty channel, a fresh key exchange is started). Chat messages are encrypted with that channel key before they are sent. The server relays the key under each member's session key.

## Using the client

```
java -jar client/target/infuser-client-x1.0.0.jar <server-ip> <port>
```

| Command | Description |
|---|---|
| `.list` | List available channels with member counts |
| `.join <roomID>` | Join the channel with the given name (case-insensitive) |

You must join a channel before you can chat. The prompt shows your current channel and its occupancy, e.g. `[general] (2/50) | ~alice >`.

**Later runs**: enter your token password to log in.

> The token is bound to your OS user, OS and architecture, so it cannot be copied to another machine or account (register again there). Run the client from the same directory each time, since `server_fingerprint.key` and `.enc_auth_token` are looked up in the working directory.

## Server administration (optional)

The server works out of the box. Anything below is only needed to go beyond the default `general` channel. Administration is done directly in the SQLite database (`sqlite3 inf_dev.db3`), and **the server must be restarted** to pick up new channels or IP list changes.

**Add channels**

```sql
INSERT INTO room_data (title, threshold, states) VALUES ('staff', 5, 'PRIVATE');
```

| Column | Meaning |
|---|---|
| `title` | Channel name. Titles starting with `*` are ignored. |
| `threshold` | Maximum number of simultaneous members |
| `states` | Comma-separated list of `PRIVATE`, `LOCKED`, or empty |

| State | Effect |
|---|---|
| `PRIVATE` | Only users holding the permission `<channel title>.access` can join |
| `LOCKED` | Messages sent to the channel are not delivered (read-only) |

**Give a user access to a private channel** (comma-separated, read at login):

```sql
UPDATE user_data SET permissions = 'staff.access' WHERE username = 'alice';
-- several: 'staff.access,ops.access'
```

**IP whitelist / blacklist**

```sql
INSERT OR REPLACE INTO ip_access (ip_address, status) VALUES ('203.0.113.7', 'blacklisted');
INSERT OR REPLACE INTO ip_access (ip_address, status) VALUES ('127.0.0.1',   'whitelisted');
```

Blacklisted IPs are always dropped. With `isWhitelisted: true`, **only** whitelisted IPs may connect, so whitelist `127.0.0.1` before testing locally.

| Table | Columns |
|---|---|
| `user_data` | `username` (PK), `permissions`, `token` |
| `room_data` | `title` (PK), `threshold`, `states` |
| `ip_access` | `ip_address` (PK), `status` (`whitelisted` / `blacklisted`) |

## Configuration reference

`config.yml` is created in the server's working directory on first start. Edit it and restart the server to apply changes.

```yaml
server:
  port: 1207
  isWhitelisted: false
  database:
    path: inf_dev.db3
```

| Key | Type | Default | Description |
|---|---|---|---|
| `server.port` | int | `1207` | TCP port the server listens on |
| `server.isWhitelisted` | bool | `false` | Restrict connections to whitelisted IPs |
| `server.database.path` | string | `inf_dev.db3` | Path to the SQLite file (created if missing) |

All server files are created relative to the directory the server is started from, so start it from the same place each time.

## Files created at runtime

All of these are git-ignored.

| File / directory | Created by | Contents |
|---|---|---|
| `config.yml` | server | Server configuration, copied from the bundled default |
| `inf_dev.db3` (name set in config) | server | Users, channels, IP lists |
| `id_keys/` | server | RSA identity key pair (`server_fingerprint.key`, `private_signing.key`) |
| `server_logs/` | server | One log file per server session |
| `server_fingerprint.key` | client | Pinned server public key |
| `.enc_auth_token` | client | Encrypted login token |

> Back up `id_keys/` and keep `id_keys/private_signing.key` private. If the identity key is lost or regenerated, every client that pinned the old public key refuses to connect until its `server_fingerprint.key` is deleted.

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
| `client` | `infuser-client` | Terminal chat client, packaged as a self-contained ("shaded") jar |

## Tests

The `shared-packets` module has unit tests (JUnit 4) for the code that carries the security guarantees:

```bash
mvn -pl shared-packets test
```

| Area | What is checked |
|---|---|
| Key exchange (ECDHE + HKDF) | both sides derive the same AES-256 key; a different salt, context string or peer gives a different key |
| Server identity (RSA) | a signature verifies only for the pinned key and the exact EC key that was signed; tampered or substituted keys are rejected |
| Packet encryption (AES-GCM) | encrypt/decrypt round trip; a fresh IV per message; a flipped bit in the IV, ciphertext or tag, a truncated payload, or the wrong key is rejected |
| Untrusted input | negative, oversized, truncated or absurd (`Integer.MAX_VALUE`) length fields are rejected before anything is allocated; packets are capped at 1 MiB |

The `server` and `client` modules have no automated tests.

## Security notes

What the design does and does not protect against, so you know what you are trusting:

- **The server is trusted with channel keys.** It relays channel keys between members (re-wrapped under each member's session key), so a malicious server operator can read channel traffic. Only run a server you trust.
- **Trust on first use.** The client pins the server's public key the first time it connects. This protects against impersonation afterwards, but not against an attacker who intercepts that very first connection. Verify the server's key through another channel if that matters to you.
- **No replay protection.** Packets carry no sequence number or timestamp, so an attacker on the network path could replay, drop or reorder encrypted packets within a session (they still cannot read or forge them).
- **Random 96-bit IVs.** Each message uses a fresh random IV under AES-GCM, which is safe at chat volumes. Because the IV is random rather than a counter, a very large number of messages under one key would eventually call for key rotation.
- **Untrusted input is bounded.** Every length read from the network is validated before anything is allocated, and packets are capped at 1 MiB.

## Scope

Infuser is deliberately small. Text chat over a command-line client is all it does. Channels, permissions and IP lists are managed in SQL, with no in-app admin commands. The points under [Security notes](#security-notes) are known and intentionally left for the successor project.

## Troubleshooting

**`release version 22 not supported` / `invalid target release: 22`**: you are building with an older JDK. Install JDK 22+ and make sure `JAVA_HOME` points to it.

**`Could not find artifact ...shared-packets:jar:x1.0.0` when starting the server**: run `mvn clean install -DskipTests` from the repository root first so the shared module is installed locally.

**`default server configuration file could not be loaded`**: there was no `config.yml` in the directory you started the server in, and the bundled default could not be found on the classpath. Rebuild with `mvn clean install -DskipTests`, or create `config.yml` by hand as shown in [Configuration reference](#configuration-reference).

**Client prints a usage message**: pass the server address and port: `java -jar client/target/infuser-client-x1.0.0.jar <ip> <port>`.

**Client refuses to connect after the server was reinstalled or its keys were regenerated**: the pinned key no longer matches. Delete `server_fingerprint.key` on the client to trust the new key (only do this if you expected the change).

**`Token identity verification failed`**: wrong token password, or the token file was created under a different OS user, OS or architecture. Delete `.enc_auth_token` and register again.

**`You're already logged in from another instance!`**: the same account is connected elsewhere. Two clients started from the same directory share one token, so start the second one from a different directory (see Quick start, step 4).

**A channel I added does not show up in `.list`**: channels are read at server startup. Restart the server.

## License

Released under the [CC0 1.0 Universal](LICENSE) public domain dedication.
