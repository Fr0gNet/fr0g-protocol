
### Detailed Explanation of the fr0g Protocol

fr0g is a simple, lightweight protocol designed to publish **immutable, censorship-resistant content** directly on the Stellar blockchain (currently on testnet, with mainnet support in development).

The core idea is to turn Stellar — a fast, low-fee payment blockchain — into a **decentralized file system** where:
- Data is stored as ManageData entries in Stellar accounts
- Every piece of content is tied to a human-readable, permanent **fr0g ID**
- Large files are split into 64-byte chunks and distributed across a chain of linked accounts
- Content is privately editable (only the secret key owner can modify or delete)
- Deleting content unlocks ~99% of the locked reserve (minus the base 10 XLM account reserve)

#### Core Principles of the Protocol

1. **fr0g ID = reversed Stellar address + prefix**  
   - A fr0g ID is a Stellar address (starting with `G…`) reversed + prefixed with `fr0g`  
   - Example:  
     Stellar: `GBN5Z…`  
     fr0g ID: `fr0g…Z5NBG`  
   - This makes IDs short, readable, and easy to share (like a decentralized domain)

2. **Fixed 64-byte chunking**  
   - Each ManageData entry can hold at most 64 bytes of value  
   - Files are split into 64-byte chunks (padded with `0xFF` if needed)  
   - Each chunk is stored with the key format:  
     `fr0g:f<index>c<chunk_number>:<mime_type>`

3. **Multiple indices (multiple files per root account)**  
   - One fr0g ID (root account) can store many files, each under a different index (0, 1, 2, …)  
   - Index 0 is the default “main file”  
   - Keys are isolated per index: `fr0g:f0c…`, `fr0g:f1c…`, etc.

4. **Automatic chaining for large files**  
   - When an account runs out of slots (~500 ManageData entries ≈ 32 KB useful)  
   - A new child account is created  
   - A link is written: `fr0g:next_f<index>` = fr0g ID of the child  
   - The viewer automatically follows the chain

5. **MIME type embedded in chunk keys**  
   - The MIME type is stored in the first usable chunk (after `:` in the key)  
   - Example: `fr0g:f0c1:text/html+gzip` → HTML file compressed with gzip  
   - The viewer uses this MIME to decide rendering (iframe, img, pre, etc.)

6. **Automatic compression**  
   - Supports **gzip** and **Brotli** (Brotli preferred)  
   - If content is compressible (text/*, json, js, css…) and savings ≥ 10%, it compresses  
   - Adds suffix `+gzip` or `+br` to the MIME in the key  
   - Viewer automatically decompresses on read

7. **Deletion & fund recovery**  
   - `remove_file(index)` deletes all chunks and next_f for that index across the chain  
   - `remove_all()` deletes everything (all fr0g:* keys)  
   - Every removed ManageData entry unlocks **0.5 XLM** of reserve  
   - Only the 10 XLM base reserve per account remains locked
```

### Updated README.md (with gzip now confirmed working)

I have appended the detailed protocol explanation at the end, updated the version/features to reflect that **gzip is now fully working**, and kept everything else almost identical as requested.

```markdown
# fr0g – Protocol for Immutable On-Chain Storage on Stellar

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](http://www.apache.org/licenses/LICENSE-2.0)
**Current version:** v0.2.x (gzip fully working, multi-index, standalone viewer)

## What is Fr0gNet?

**fr0g** is a lightweight **protocol / application layer** built on top of the Stellar blockchain that enables a fully decentralized, censorship-resistant web file system.

It allows anyone to publish websites, HTML pages, JSON, images, or small files **directly on-chain**, tied to a permanent and immutable address called a **fr0g ID** (e.g. `fr0g24taf546wdpvrlqp5ochagmnvcjt2tnyjmmlkbrwv227mvzg7bjn53ag`).

**Fr0gNet** is the broader ecosystem name that includes:
- the fr0g protocol itself
- the standalone client-side viewer (`browser.html`)
- the Python client library (`fr0g` package)
- future tools, SDKs, and extensions

### Core Features

- **100% censorship-resistant** — once published, no one (not even you without the secret key) can remove or modify the content
- **No servers, no centralized hosting, no Cloudflare, no traditional domain**
- **fr0g ID = decentralized domain** — anyone with the ID can resolve and view the content
- **Privately editable** — only the secret key owner can update or delete
- **Client-agnostic** — no official client required; anyone can build their own resolver/viewer
- **Near-full fund recovery** — deleting data unlocks ~99% of the locked reserve (minus the 10 XLM base account reserve)
- **Built-in gzip compression** — automatic and fully working for text-based content (HTML, JSON, plain text) → 5–10× more effective storage usage
- **Lightweight & simple** — minimal dependencies, pure Python implementation

### Current Status

The protocol is fully operational on **Stellar testnet** (completely free for testing and development, with generous Friendbot funding).

**Mainnet support is in active development**:
- Child accounts will require manual funding (no Friendbot equivalent on mainnet)
- All other logic (chaining, multi-index, gzip compression, viewer) remains the same
- Once live on mainnet, publishing will be permanent until you decide to delete (and recover almost all funds)

### Cost & Reserve Overview

| Scenario                     | Stellar Testnet (current) | Stellar Mainnet (reserve) |
|------------------------------|---------------------------|----------------------------|
| 10 KB text                   | $0 (free with Friendbot)  | ~90 XLM (~$10–20)         |
| 100 KB text (with gzip)      | $0                        | ~190–390 XLM (~$20–80)    |
| 1 MB text (with gzip)        | $0                        | ~990–1.990 XLM (~$100–400)|
| Funds recoverable on delete  | N/A (testnet free)        | ~99% (minus 10 XLM base)  |

- **Testnet**: **100% free** — Friendbot funds root and child accounts automatically
- **Mainnet**: reserve is locked but almost fully recoverable on deletion (minus 10 XLM base account reserve)
- **Fee per transaction**: ~0.00001–0.0001 XLM (extremely low)

### Installation (Testnet)

```bash
git clone https://github.com/your-username/fr0g-protocol.git
cd fr0g-protocol/fr0g
pip install -r ../requirements.txt
```

Or install directly from git:

```bash
pip install git+https://github.com/your-username/fr0g-protocol.git
```

### Next Steps / Roadmap

- Full mainnet support (Stellar)
- Child account funding improvements (manual or sponsored)
- Brotli / zstd compression in addition to gzip
- JavaScript SDK for browser integration
- Interactive CLI (`fr0g upload`, `fr0g view`, `fr0g remove`)
- Optional human-readable name integration (e.g. via ENS-like service on Stellar)

### Detailed Explanation of the fr0g Protocol

fr0g is a simple, lightweight protocol designed to publish **immutable, censorship-resistant content** directly on the Stellar blockchain (currently on testnet, with mainnet support in development).

The core idea is to turn Stellar — a fast, low-fee payment blockchain — into a **decentralized file system** where:
- Data is stored as ManageData entries in Stellar accounts
- Every piece of content is tied to a human-readable, permanent **fr0g ID**
- Large files are split into 64-byte chunks and distributed across a chain of linked accounts
- Content is privately editable (only the secret key owner can modify or delete)
- Deleting content unlocks ~99% of the locked reserve (minus the base 10 XLM account reserve)

#### Core Principles of the Protocol

1. **fr0g ID = reversed Stellar address + prefix**  
   - A fr0g ID is a Stellar address (starting with `G…`) reversed + prefixed with `fr0g`  
   - Example:  
     Stellar: `GBN5Z…`  
     fr0g ID: `fr0g…Z5NBG`  
   - This makes IDs short, readable, and easy to share (like a decentralized domain)

2. **Fixed 64-byte chunking**  
   - Each ManageData entry can hold at most 64 bytes of value  
   - Files are split into 64-byte chunks (padded with `0xFF` if needed)  
   - Each chunk is stored with the key format:  
     `fr0g:f<index>c<chunk_number>:<mime_type>`

3. **Multiple indices (multiple files per root account)**  
   - One fr0g ID (root account) can store many files, each under a different index (0, 1, 2, …)  
   - Index 0 is the default “main file”  
   - Keys are isolated per index: `fr0g:f0c…`, `fr0g:f1c…`, etc.

4. **Automatic chaining for large files**  
   - When an account runs out of slots (~500 ManageData entries ≈ 32 KB useful)  
   - A new child account is created  
   - A link is written: `fr0g:next_f<index>` = fr0g ID of the child  
   - The viewer automatically follows the chain

5. **MIME type embedded in chunk keys**  
   - The MIME type is stored in the first usable chunk (after `:` in the key)  
   - Example: `fr0g:f0c1:text/html+gzip` → HTML file compressed with gzip  
   - The viewer uses this MIME to decide rendering (iframe, img, pre, etc.)

6. **Automatic compression**  
   - Supports **gzip** (fully working) and **Brotli** (in development)  
   - If content is compressible (text/*, json, js, css…) and savings ≥ 10%, it compresses  
   - Adds suffix `+gzip` or `+br` to the MIME in the key  
   - Viewer automatically decompresses on read

7. **Deletion & fund recovery**  
   - `remove_file(index)` deletes all chunks and next_f for that index across the chain  
   - `remove_all()` deletes everything (all fr0g:* keys)  
   - Every removed ManageData entry unlocks **0.5 XLM** of reserve  
   - Only the 10 XLM base reserve per account remains locked

### Contact & Support

- X: @fr0gnet_ (placeholder)
- Discord: discord.gg/fr0gnet (placeholder)
- XLM donations (testnet or mainnet): `GDJDYV2WWEWXR4TUQY3TOCA5AF55PXNKRDQT7U2T3C6ZKARMOHYLPHWZ`

🐸 **Building a web that nobody can shut down.**

Star ✭ if you like the vision! Pull requests welcome.

Ora possiamo passare a qualsiasi altra feature (mainnet funding manuale, viewer update, repo setup). 🐸
