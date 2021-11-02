# Covert Format Specification

## File structure

A file begins with a cryptographic header, followed by one or more encrypted authenticated blocks. The sole purpose of the header is to provide the keys needed to decrypt all the blocks where all remaining data is stored.

`header` `block1` `block2`...

The header usually begins with a nonce of 12 bytes, followed by up to 16 authentication slots. This allows for up to 16 different passwords or up to 8 public key recipients (each takes two slots), or any combination of. The size of the header varies depending on the authentication methods used. In addition to the normal format, there are special cases for wide-open (no auth required), single password and single pubkey, making the header shorter in these frequently used modes.

| Header format | Description |
|:---|:---|
| `nonce:12` | Single password `key = argon2(pw, nonce)` or wide-open `key = zeroes(32)`. |
| `ephpk:32` | Single pubkey `key = sha512(nonce + ecdh(eph, peer))[:32]` |
| `ephpk:32` `auth1:32` `auth2:32` ... | Multiple authentication methods (pubkeys and/or passwords). |

`ephpk` stores an ephemeral public key which is always recreated for each file, even if only passwords are used (but may be substituted by random bytes then). The nonce is always the initial 12 bytes of a file, in all modes.

Note that the single pubkey and the multiple auth modes are actually the same, and need no separate implementation.

In the multiple authentication mode there are up to 19 *additional authentication slots*. Keys for each individual auth are derived as in the single password/pubkey modes and stored in an array. The file key is `auth[0]` and is not stored in file, while all others are stored in file as `authn = xor(auth[0], auth[n])`. Decoy entries with random bytes and shuffling the auth array can be used to obscure from recipients how many others there were.

Each block is encrypted and authenticated by chacha20-poly1305, using nonce and key derived from header. The first block is mandatory. Its starting offset depends on the number of recipients, and it ends at any byte up to 1024 offset from file beginning. All combinations of slots, methods and block offsets must be attempted until the decryption succeeds, as verified by the Poly1305 authentication. This takes very little time and false matches are impossible.

The first block cipher has as additional authenticated data all header bytes (i.e. everything until the position where the block was found), to prevent any manipulation. Other blocks have no AAD. The nonce is incremented in little endian (i.e. the lowest bit of the first byte always changes). The first block uses a nonce one greater than the header, the second block one greater than the first, etc. The key stays the same throughout the file but is different on each new file even if identical authentication was used.

Block format:
```
data:bytes nextlen:uint24 tag:bytes[16]
```

The checksum tag comes directly from the ChaCha20-Poly1305 algorithm and is automatically added/removed by cryptographic libraries. The nextlen field is an unsigned int24 denoting the number of data bytes in the next block. If the value is 0, reading stops and no more blocks are processed, thus this format requires no information of where the stream ends but can provide for that information internally.

Only the first block can have zero bytes of data and only when the file is completely empty. Otherwise each block including the last one must carry at least one byte of data. A block can be up to 16 MiB + 18 bytes in external size (nextlen max value plus 19 bytes of structures).

The data stored here, as concatenated from all the blocks, is referred to as the raw stream, and it can be of any length of bytes from 0 to infinity. For normal use, the Covert files always contain archive data.

## Archive format

### Overview

Inside the raw stream, there is a separate msgpack-based container format that allows multiple file attachments, signatures and other features not supported by the plain block stream. The archive is independent of the block layer, and any of its structures may pass block boundaries. For purposes of real-time streaming, an encoder may manipulate block lengths to allow immediate transmission of data over the pipes.

Only the index header and other structures use [MessagePack](https://msgpack.org/) objects. Data is stored as plain bytes rather than msgpack binary objects to reduce the space needed and to increase performance because msgpack is not well suited for very large data.

### Layout

* Short format: `size:int` `file1-data` `padding`
* Advanced format: `index:dict` `file1-data` `file2-data`... `padding`

The decoder knows which format is being used by the type of the first non-NIL msgpack object found.

Typical short messages can be stored in the short format with a minimal overhead of only one byte. The advanced format has a very moderate overhead which should be insignificant in any situations where it might be needed. Data from different files can be simply concatenated because the index already tells their sizes. The advanced format also supports streaming of files for which the size is not known in advance (each chunk of data begins with len:int and the file ends when the length is zero).

### The Index

A dictionary, optionally with key `f` containing a list of files. Each file is a dict with optional keys `n: filename` and `s: size`, but this is subject to change into a list instead, avoiding some overhead of key names and simplifying the code. If no size is given, the file uses streaming (length before each chunk of data).

The short format is easily implemented by converting the int value decoded into a corresponding full index:
```javascript
{f: [{s: value}]}
```

As of now no other index fields are specified, but likely additions include `s` key with a list of sender/signature names and public keys (both optional of course). [X3DH](https://signal.org/docs/specifications/x3dh/) and [Double Ratchet](https://signal.org/docs/specifications/doubleratchet/) metadata are also possible additions.

### Padding
The padding is a randomly chosen number of `\xC0` bytes (msgpack NILs), and it can be added at any point where msgpack is expected, although typically it is left until the end of archive. A preferred size should be chosen e.g. as a proportion such as 5 % of total size. The maximum preferred size can be clamped to some upper bound to limit the waste of space. Never clamp the actual size, as doing so defeats the purpose of padding. The actual value is picked from the exponential distribution:

```python
padsize = int(round(random.expovariate(1.0 / size)))
```

This gives good variation in the ciphertext length, such that one cannot guess the length and the meaning of a message by looking at the size of the ciphertext. The *mean length* will be `size` bytes. Most of the time the padding is shorter than that but occassionally it can be many times longer.

## Signatures

Signatures may be added after the otherwise final block, or as separate detached files, with the intention that signatures may be added and removed without rewriting the original file, which would invalidate any existing signatures. The signatures also look like random data, although the same bytes are produced if the same key signs the same file again. There may be multiple signature blocks appended to a file.

Rather than hashing all the data, the Poly1305 tags already calculated for each block are used. This is far faster than running the slow hash function over the entire data and yet provides equal protection.

```python
h = sha512(header)
for ciphertext in blocks:
    h = sha512(h + ciphertext[-16:])  # Poly1305 tag
filehash = h
```

The hashes form a *blockchain* where signing the final hash is sufficient to prove that no modification to the data was made at any point.

A signature block is 80 bytes, containing a 64-byte signature encrypted into a single Chacha20-Poly1305 block, where the encryption *key* is `filehash[:32]` and the *nonce* is `hash(filehash + pk)[:12]`, where pk is the recipient public key (32 bytes). Possession of both the **full original file** and the **public key** used to sign is necessary to even decrypt the signature, even if the original file used `--wide-open`, as keys are not stored with the signature itself.

Once decrypted, the signature data MUST be verified using the [XEd25519](https://signal.org/docs/specifications/xeddsa/) algorithm because simply opening the block gives no verification. The final block hash is the *message* to sign. For this part, the normal Curve25519 (Montegomery) used for block cipher need to be converted to the corresponding Ed25519 keys, which are only used once the signature block is decrypted, to verify the signature itself.

The archive index may specify that the file is signed, including the corresponding public key and name. This allows for key exchange and prevents anyone but the intended recipients from removing that signature without being noticed.

## Ascii armor

Covert files and detached signatures may be converted into text strings that are easy to copy&paste e.g. on online discussions. A Covert message can even fit in a Tweet. URL-safe Base64 without padding is used.

There are no headers to make it distinct of any random data encoded in Base64, but for maximal privacy and the best performance, raw binary files should be used instead whenever possible.

```
UMtgDS4BzWHx-1zPfKFPpyUnLfHzlUIO04bF35y4tN4VUcXqGuJDhYftvs6fpQ
```

## Miscellaneus details

### Extensions

Single character dict keys are reserved to the format. Users may add custom metadata to any dict by using multi-letter key names.

The use of any unnecessary metadata, e.g. any names of programs used, is heavily discouraged.

### Endianess

All integers are unsigned and encoded in **little endian**, unless specified otherwise by foreign formats such as MsgPack (which is big endian).

### Character encoding

Text given as a message in terminal or other text input should be normalized by removing any trailing whitespace on each line. Lines must be terminated by LF only. There is no LF after the final line, all trailing newlines should be removed.

All Unicode, filenames and passwords in particular, must be normalized into **NFKC format**. Apple devices natively use NFD, which causes problems with passwords and filenames if not properly normalized. Strings extracted from Covert files should alike be transformed back to platform-native format as needed.

Finally, strings are always encoded in UTF-8 without BOM. Any text stored in MsgPack objects uses the string rather than the binary format.

### Argon2 password hashing

The time cost depends on the number of **bytes** in the UTF-8 encoded password. Passwords shorter than 8 bytes are not accepted at all. Passwords shorter than 8 *characters* in foreign languages may be permissible.

Passwords are always prehashed with `sha512("covert:" + password)[:32]` to obtain the input to Argon2 (in binary, not hex). Normally this occurs directly before Argon2, without ever storing the prehash anywhere, but this stage is to allow storage and transmission of a prehash rather than plain text e.g. in keystores or web frontends (which still need to provide the time cost parameter separately).

|Parameter|Passphrase bytes|Value|
|---|---:|---|
|hash_len||32||
|time_cost|8|512|
||9|128|
||10|32|
||≥ 11|8|
|mem_cost||100 MiB|
|parallelism||1|
|type||Argon2id|

Hashing the shortest passwords may take several minutes on mobile devices or browsers and a dozen seconds even on fast PCs. This is necessary to secure such weak passwords. Even with the time cost tweak, a longer password will in general be much more secure. Users are encouraged to choose longer passphrases to avoid the delay.

### Real-time streaming

If the file length is not known in advance, no length is given in the index, and instead a MsgPack int object before each chunk tells how many bytes to read. Such a file is terminated by a MsgPack 0. Usually this occurs in a non-realtime context where the encoder may wait until a full block is done before sending it out.

The format also supports transmission of smaller blocks without delay. This requires coordination between the archive and the block layer regarding the next block lengths. It is recommended to choose a reasonably large next size (e.g. 1024) even if the data length is not known, and to fill any unused space with padding if needed, rather than to create 1-byte blocks with a huge overhead just to be safe.
