# AES Shellcode Payload Encryptor

A small Windows utility that encrypts raw shellcode using AES-256-CBC.

The project provides a simple and reliable way to encrypt binary payloads using native Windows cryptographic APIs. It reads a raw shellcode file, generates a random AES key and initialization vector, encrypts the data, and exports the result in formats that can be directly reused in C source code. The implementation focuses on clarity, correctness, and ease of use, without adding unnecessary complexity.
---

## Features

- AES-256-CBC encryption
- Random key and IV generation
- PKCS#7 padding
- Outputs encrypted payload, key, and IV as C arrays

## Build

```bash
gcc encrypt_payload.c modules/crypto.c -o encrypt_payload.exe -lAdvapi32
```

## Usage

```bash
encrypt_payload.exe <shellcode_file>
```

## Output

Files generated in `payload/`:

- `shellcode_aes.bin` – encrypted shellcode (binary)
- `shellcode_aes.txt` – encrypted shellcode as C array
- `key_iv.txt` – AES key and IV as C arrays

---

## License

MIT License


## Disclaimer

For educational and research use only.
