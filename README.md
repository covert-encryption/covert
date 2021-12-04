<img src="https://github.com/covert-encryption/covert/blob/main/docs/logo.webp?raw=true" width="220" alt="Logo" align="left">

# Covert Encryption

*A file and message encryptor with strong anonymity*

* **ChaCha20-Poly1305** stream cipher with authentication
* **Argon2** secures shorter passwords against cracking
* **Curve25519** public key encrypt & sign with [SSH](https://medium.com/risan/upgrade-your-ssh-key-to-ed25519-c6e8d60d3c54), [Age](https://age-encryption.org/) and [Minisign](https://jedisct1.github.io/minisign/) keys

## Anonymity, privacy and authenticity

The encrypted archive looks exactly like random data, providing **deniability**. Every byte is protected so that not only is reading prevented but **authenticity** is also verified, protecting your data against any outsiders, and files may also be **signed** if necessary.

Other encryption tools add unencrypted headers revealing the recipients and other metadata. Covert was created to address this very problem, to stop *all* information leakage.

A message (base64 or binary) has no headers or anything else that could be recognized:
```
R/i7oqt9QnTnc6Op9gw9wSbYQq1bfYtKAfEOxpiQopc0SsYdLa12AUkg0o5s4KPfU6eZX59c4SXD2F8efFCEUeU
```

Covert generates easy passphrases like `oliveanglepeaceethics` for the above. The encoded message includes random padding to hide the length of the message and it is still shorter than others. For comparison, `gpg` needs six lines instead of one and still ends up revealing the exact length of the message.

## Try it!

[Python](https://www.python.org/downloads/) `pip` will add `qcovert` and `covert` on your system:

```
pip install covert[gui]

qcovert      # Run GUI, or
covert       # Run in terminal
```

## File I/O speeds matching the fastest SSDs

<img src="https://github.com/covert-encryption/covert/blob/main/docs/benchmark.webp?raw=true" width="700" alt="Benchmark results. Covert up to 4 GB/s.">

Covert is the fastest of all the popular tools in both encryption (blue) and decryption (red).

Program|Lang|Algorithms|Operation
|---|---|---|---|
Covert | Python | chacha20‑poly1305 sha512‑ed25519 | encrypt with auth and signature
Age | Go | chacha20-poly1305 | encrypt with auth
Rage | Rust | chacha20-poly1305 | encrypt with auth
OpenSSL | C | aes256-ctr (hw accelerated) | encrypt only
GPG | C | aes128-cfb, deflate | encrypt with auth and compression
Minisign | C | blake2b-512 ed25519 | signature only (for reference)

## A few interesting features

Files of any size may be attached to messages without the use of external tools, and without revealing any metadata such as modification times.

A completely different ciphertext is produced each time, usually of different size, even if the message and the key are exactly the same. Other crypto tools cannot do this.

Covert messages are much shorter than with other cryptosystems, accomplished by some ingenious engineering.

A key insight is that a receiver can *blindly* attempt to decrypt a file with many different keys and parameters until he finds a combination that authenticates successfully. This saves valuable space on short messages and improves security because no plain text headers are needed.

![Screenshot](https://github.com/covert-encryption/covert/raw/main/docs/covert-gui.webp)

## A secure desktop app

Covert comes with a graphical user interface built in. Unlike PGP GUIs, Covert does not use external CLI tools but instead does everything inside the app. Storing the plain text message on disk at any point exposes it to forensic researchers and hackers who might be scanning your drive for deleted files, and unfortunately there have been such leaks with popular PGP programs that use temporary files to communicate with external editors or with the `gpg` tool.

## Additional reading

* [Covert Format Specification](https://github.com/covert-encryption/covert/blob/main/docs/Specification.md)
* [Covert Encryption Security](https://github.com/covert-encryption/covert/blob/main/docs/Security.md)
* [Reducing Metadata Leakage](https://petsymposium.org/2019/files/papers/issue4/popets-2019-0056.pdf) (a related research paper)
* [The PGP Problem](https://latacora.micro.blog/2019/07/16/the-pgp-problem.html)

Covert is in an early development phase, so you are encouraged to try it but avoid using it on any valuable data just yet. We are looking for interested developers and the specification itself is still open to changes, no compatibility guarantees.
