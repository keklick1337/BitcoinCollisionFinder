# Bitcoin Wallet Collision Finder

*(c) Vladislav Tislenko (keklick1337), 19 Dec 2024*

This tool attempts to generate random Bitcoin private keys and derive corresponding addresses (P2PKH, P2WPKH-P2SH, and P2WPKH) in search of collisions with a provided list of known addresses. The primary goal is research and testing—finding an actual collision is astronomically improbable, but this software can be used as a demonstration or benchmark.

## Features
- Generates three types of Bitcoin addresses from a single private key:
  - **P2PKH (Legacy):** starts with '1'
  - **P2WPKH-P2SH:** starts with '3'
  - **P2WPKH (Bech32):** starts with 'bc1'
- Optionally disable generation of any address type for testing or performance considerations.
- Can load a large list of known addresses from a file and check for collisions during generation.
- Parallel generation with configurable thread count.
- Periodic speed reporting in addresses per second.
- Test mode (`--test`) to quickly generate a small number of keys and verify correctness.
- Uses `/dev/urandom` for seeding randomness, ensuring unique keys across runs.

## Download Test Address List
For testing, you can download a sample list of Bitcoin addresses with balances (as of Dec 19, 2024) here:

[btc_wallets_with_balance_dec19_2024.txt.gz](https://fileshare-local.trustcrypt.net/btc_wallets_with_balance_dec19_2024.txt.gz)

This file is meant for demonstration only. The addresses inside are public and may or may not still hold balances by the time you test.

## Requirements
- C++11 or newer
- OpenSSL (for SHA256 and RIPEMD160)
- `libsecp256k1`
- A working `g++` compiler
- `pkg-config` (optional, for automatic detection of library paths)

On Debian/Ubuntu:
```bash
sudo apt-get update
sudo apt-get install -y build-essential libssl-dev libsecp256k1-dev pkg-config
```

On macOS (with Homebrew):
```bash
brew install openssl libsecp256k1 pkg-config
```

## Building

1. Run the `configure` script to detect and verify dependencies:
   ```bash
   ./configure
   ```
   It checks for OpenSSL, secp256k1 headers, and linking. On success, it creates `Makefile.config`.

2. Compile:
   ```bash
   make
   ```
   
   This will produce `bin/gen_key`.

## Usage

```bash
./bin/gen_key [options]
```

**Options:**
- `-t <threads>`: Number of threads (required unless `--test` is used).
- `-f <file>`: File with known addresses to check for collisions (required unless `--test` is used).
- `-o <outfile>`: Output file for results (default: `out.list`).
- `-u <interval>`: Update interval for speed report in seconds (default: 1).
- `--test`: Run in test mode, generate a few keys and exit.
- `--disable-p2pkh`: Do not generate/check P2PKH addresses.
- `--disable-p2wpkh-p2sh`: Do not generate/check P2WPKH-P2SH addresses.
- `--disable-p2wpkh`: Do not generate/check P2WPKH addresses.
- `-h, --help`: Show this help message.

**Example:**
```bash
./bin/gen_key -t 4 -f btc_wallets_with_balance_dec19_2024.txt -o results.list -u 2
```

This will start generating addresses using 4 threads, checking against `btc_wallets_with_balance_dec19_2024.txt` for collisions, outputting matches to `results.list`, and printing speed updates every 2 seconds.

## Disclaimer

This software is purely for demonstration and research. The probability of finding a collision with real-world Bitcoin addresses is effectively zero. Do not rely on this tool to break Bitcoin security. Use it at your own risk and only for educational or testing purposes.