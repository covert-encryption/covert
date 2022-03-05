# Covert Format Specification

## File structure

A file begins with a cryptographic header, followed by one or more encrypted authenticated blocks. The sole purpose of the header is to provide the keys needed to decrypt all the blocks where all remaining data is stored. Each block identifies if it is followed by more blocks, and if so, the block length. Signed files append 80-byte signature blocks at the end for each signature (as identified within the file). The whole stream is self-contained, it knows where it stops, and does not need to rely on end-of-file for that.

`header` `block0` `block1`...`blockN` `signature`*

The header contains tokens neded for decrypting block0, given suitable passwords or private keys. `ephash` stores an ephemeral public key hash, even if only passwords are used (but may be substituted by random bytes then). The nonce is always the initial 12 bytes of a file, either as a separate field (short mode) or by using the initial bytes of `ephash` or `encrheader`. There may be up to 20 recipients, each a shared password or a public key. A short mode is provided for simple cases where 12 bytes header overhead is sufficient. Otherwise the header size is 32 bytes times the number of recipients, although decoy entries filled with random bytes may be added to obscure the number of recipients.

| Header format | Mode | Description |
|:---|:---|:---|
| `nonce:12` | Short | Single password `key = argon2(pw, nonce)` or wide-open `key = zeroes(32)`. |
| `ephash:32` | Advanced | Single pubkey `key = sha512(nonce + ecdh(eph, receiver))[:32]` |
| `ephash:32` `auth1:32` `auth2:32` ... | Advanced | Multiple authentication methods (pubkeys and/or passwords). |
| `encrheader:50` | Ratchet | Conversation using Signal's Double Ratchet (forward secrecy). |

The ratchet mode header contains `rkey:32` `PN:2` encrypted with ChaCha20-Poly1305 using previously negotiated header keys. The rkey is used in ECDH exchange to derive new keys, and then the Double Ratchet is used to derive the file key. PN is the number of messages sent using the previous chain, such that skipped or lost messages can be detected by the recipient.

The short mode saves space for the commonly used single password and wide-open cases, versus using the advanced mode. The header is only 12 bytes and the auth key is directly used as the file key used to encrypt all the blocks.

The advanced mode uses 0-19 *additional authentication slots*, thus the header size varies between 32-640 bytes. Note that the single pubkey and the multiple auth modes actually share the same implementation and are shown here separately only for illustration. 32-byte keys for each individual auth are derived as in the single password/pubkey modes and stored in `keys` array. Entries with random 32 bytes may be added to obscure the number of recipients.

It is critical to **eliminate any duplicates** within the `keys` array, caused by duplicate passwords or recipient keys. Be sure to do this *after* any processing of recipient strings, as different input formats could be producing the same key (depending on your implementation), but it is recommended filter out duplicates also before any hashing (provides depth of security and avoids calculating the same keys multiple times).

The first key becomes the file key `key = keys[0]`, while the additional auth slots are filled with `authn = key ⊕ keys[n]` (xorred with the file key). The receiver tries opening a file using any of his keys directly as key on block0 or by xorring it with each 32-byte auth slot (up to 19 of them, if permitted by file size).

Each block is encrypted and authenticated by chacha20-poly1305, using nonce and key derived from header. Block0 is mandatory. Its starting offset depends on the number of recipients, and it ends at any byte up to 1024 offset from file beginning. All combinations of slots, methods and block offsets must be attempted until the decryption succeeds, as verified by the Poly1305 authentication. This takes very little time and false matches are impossible.

Block0 has as *additional authenticated data* all header bytes (i.e. everything until the position where the block begins), to prevent any manipulation. Other blocks have no AAD. The nonce is incremented in little endian (i.e. the lowest bit of the first byte always changes). Block0 uses the same nonce as the header, the second block one greater than the first, etc. The key stays the same throughout the file but is different on each new file even if identical authentication was used.

Block: `data` `nextlen:3` `polytag:16`

The polytag comes directly from the ChaCha20-Poly1305 algorithm and is automatically added/removed by cryptographic libraries. The nextlen field is an uint24 denoting the number of data bytes in the next block. If the value is 0, reading stops and no more blocks are processed, thus this format requires no information of where the stream ends but can provide for that information internally.

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

The short format int value `size` maps to the following advanced format index and vice versa. Implementations are expected to perform this conversion, so we can discuss only the advanced format:

```javascript
{f: [[size, null, {}]]}
```

Advanced index is a dictionary, optionally with key `f` containing a list of files.

Each file entry is a list `[size, filename, meta]`. If size is null, the file uses streaming (length before each chunk of data). Filename is null for messages, a string for attachments / archived files. Meta is a dictionary that may contain additional flags but is usually empty. Currently only `{x: True}` is defined for UNIX executable files.

As of now no other index fields are specified, but likely additions include `s` key with a list of sender/signature information. [X3DH](https://signal.org/docs/specifications/x3dh/) and [Double Ratchet](https://signal.org/docs/specifications/doubleratchet/) metadata are also possible additions.

### Padding

The padding is a randomly chosen number of `\xC0` bytes (msgpack NILs), and it can be added at any point where msgpack is expected, although typically it is left until the end of archive.

The amount of padding may be adjusted by the `--pad` parameter on covert CLI to cater for different security and space usage trade offs. The proportion `p` (default 5 %) affects the random padding amount as well as the padding applied to smallest messages such that their size (counting only content, no headers or structures) is at least `p * 500` bytes (default 25):

```python
fixed_padding = max(0, int(p * 500) - size)
```

We use a slightly non-linear formula to calculate an *effective* size, such that the smallest files receive a slightly higher proportion of padding than configured, while files in the gigabyte class are padded considerably less to avoid excessive waste of space. `log` is the natural logarithm.

```python
eff_size = 200 + 1e8 * log(1 + 1e-8 * (size + fixed_padding))
```

The random padding is drawn from exponential distribution, calculated in a numerically stable way (in double precision floating point) using two uint32 uniform random numbers `rnd1` and `rnd2` to obtain the coefficient `r` that has a mean value of 1.0 and is most of the time lower than that, but that may rise up to 45 in extremely rare occassions:

```python
r = log(2**32) - log(rnd1 + rnd2 * 2**-32 + 2**-33)
total_padding = fixed_padding + int(round(r * p * eff_size))
```

There are illustrative diagrams, further discussion and comparison to PADME padding in our [Security Documentation](https://github.com/covert-encryption/covert/blob/main/docs/Security.md#random-padding).


## Signatures

Signatures may be added after the otherwise final block, or as separate detached files, with the intention that signatures may be added and removed without rewriting the original file, which would invalidate any existing signatures. The signatures also look like random data, although the same bytes are produced if the same key signs the same file again. There may be multiple signature blocks appended to a file.

Rather than hashing all the data, the Poly1305 tags already calculated for each block are used. This is far faster than running the slow hash function over the entire data and yet provides equal protection.

```python
h = ""
for ciphertext in blocks:
    h = sha512(h + ciphertext[-16:])  # Poly1305 tag
filehash = h
```

The hashes form a *blockchain* where signing the final hash is sufficient to prove that no modification to the data was made at any point.

A signature block is 80 bytes, containing a 64-byte signature encrypted into a single Chacha20-Poly1305 block, where the encryption *key* is `filehash[:32]` and the *nonce* is `hash(filehash + pk)[:12]`, where pk is the recipient public key (32 bytes). Possession of both the **full original file** and the **public key** used to sign is necessary to even decrypt the signature, even if the original file used `--wide-open`, as keys are not stored with the signature itself.

Once decrypted, the signature data MUST be verified using the [XEd25519](https://signal.org/docs/specifications/xeddsa/) algorithm because simply opening the block gives no verification. The final block hash is the *message* to sign. For this part, the normal Curve25519 (Montegomery) used for block cipher need to be converted to the corresponding Ed25519 keys, which are only used once the signature block is decrypted, to verify the signature itself.

The archive index may specify that the file is signed, including the corresponding public key and name. This allows for key exchange and prevents anyone but the intended recipients from removing that signature without being noticed.

## Ascii armor

Covert files and detached signatures may be converted into text strings that are easy to copy&paste e.g. on online discussions. A Covert message can even fit in a Tweet. **Standard Base64 without padding** is used but when copied to clipboard Covert adds **triple-backticks** before and after such that messages are shown as code blocks in messaging apps supporting this syntax. Covert armor decode ignores any backticks around the text as well as any `>` quote marks at the beginning of each line even though **these are not parts** of the armored message nor valid Base64 characters.

There are no headers to make it distinct of any random data encoded in Base64, but for maximal privacy and the best performance, raw binary files should be used instead whenever possible.


## Argon2 password hashing

### Overview

Password authentication is tricky because there simply is not enough entropy in passwords that people are willing to type in and memorize. The minimum password length is **8 bytes** and for such weak passwords very slow hashing is used to keep them secure, while longer passwords get faster hashing.

All password inputs must be converted into Unicode Normalization Form KC, `NFKC`, and then encoded as UTF-8 bytes. This is to ensure compatibility between devices (Apple and Microsoft have incompatible encodings).

The Argon2 hashing is performed in two stages with distinct functions.
* Stage 1 is adaptive to password length, producing a 16 byte `pwhash`.
* Stage 2 combines the `pwhash` with the unique `nonce` of each file.

```python
# Normalize and encode
pw_bytes = normalize("NFKC", password).encode("UTF-8")

# Stage 1
time_cost = 8 << max(0, 12 - len(pw_bytes))
pwhash = argon2id(hashlen=16, salt="covertpassphrase", password=pw_bytes, time_cost=time_cost)

# Stage 2
authkey = argon2id(hashlen=32, salt=pwhash, password=nonce, time_cost=2)
```

The `pwhash` may be kept in device RAM or in a secure keystore in case multiple files need to be processed, avoiding some slow hashing and keeping the original password always secure. The second stage is much faster but adds necessary protection against rainbow tables and provides each file with a unique `authkey` even when the same password is reused. See the **File structure** section above for further discussion on the auth keys.

### Stage 1: Argon2 on password

|Parameter|Passphrase bytes|Value|
|---|---:|---|
|hash_len||16|
|time_cost|8|128|
||9|64|
||10|32|
||11|16|
||≥ 12|8|
|mem_cost||256 MiB|
|parallelism||1|
|type||Argon2id|

The salt is always `covertpassphrase` (16 bytes)

### Stage 2: Argon2 on nonce and pwhash

|Parameter|Value|
|---|---|
|hash_len|32|
|time_cost|2|
|mem_cost|256 MiB|
|parallelism|1|
|type|Argon2id|

Notice that in this stage the roles of salt and password are reversed because libsodium requires a salt of exactly 16 bytes, matching the pwhash but not the 12-byte nonce.

## Covert Double Ratchet

The ratchet mode enables conversations with **forward secrecy** and self-deleting message keys such that old messages cannot be read later even if one or both parties' keys are breached and the attacker has access to all ciphertext. Further, it provides **post-breach secrecy** such that even after such breach new keys are negotiated within a message round-trip such that no further communication is compromised. Messages may be received out of order or some of them may be lost but the recipient can recover the correct ordering and detect any prior missing messages.

The documentation of ratchet operation is somewhat incomplete, and for implementation you will need to consult Covert source code and Signal's [Double Ratchet with header encryption](https://signal.org/docs/specifications/doubleratchet/#double-ratchet-with-header-encryption)

### Initial messages using public keys

The sender of a public-key encrypted message may signal his capability to support Double Ratchet in replies by adding an `r: N` field in the archive index header. This should only be used when there is a single recipient, as the double ratchet only functions between two parties. Further, both parties will need to use a persistent **idstore** to keep track of the ratchet keys in use. The sender stores locally the filehash of each message sent, which becomes the header encryption key for the initial ratchet reply.

Thus Alice sends a message to Bob, advertising this capability and including her public key or a random ratchet key. Bob can respond using normal public keys but assuming that he chooses to use a ratchet, he needs to initialise in his idstore a new ratchet with the filehash of the incoming message and store it in his idstore. Note that Alice may have sent multiple initial messages, and Bob may respond to any of these, not necessarily reading the others. The initial messages do not have forward secrecy but the message number `N` (0, 1, ...) included in the archive index can be used to track lost messages.

Alice receives the message, not knowing it is from Bob, but trying all her stored keys to decrypt the encrypted header until a match is found with the filehash of the message she sent to Bob earlier. After this Alice initialises her end of the ratchet and expires the filehash from her idstore. Bob may also send multiple replies, and Alice can decrypt any of them using the same filehash but using nonce increments.

### Ratchet operation

After the initial message all further communication uses a protocol closely following Signal protocol. The root key and the initial header key from Bob to Alice is the filehash of the initial message, while all other keys are derived from the chains.

The current message number (reset to 0 after each ratchet step) is not stored within the encrypted header as in Signal, but rather encoded as the header encryption nonce, which is incremented by one on each message. Thus, the recipient tries header decryption with all its known header keys and corresponding nonces with up to 20 into the future (allowing for that many skipped messages). Whenever a message is received using the next header key (rather than the current one), a ratchet step is performed.

Any skipped message keys are stored in idstore for later use but are immediately expired.

### ECDH ratchet step

Within an ECDH step, the root chain is advanced twice, first using the new rkey just received to derive a new chain of receiving keys, and then using a newly created local rkey, deriving a new chain of sending keys. Note that the respective send/receive header keys lag one cycle behind and are updated only after a further round-trip such that the recipient can always decrypt the header he'll need for the new rkey. The change of header key is what triggers the ratchet step in receiving end, using the sender's newly created rkey included in that header.

The next header keys become the current header keys, the current message indices become the previous message indices. The old receiving chain is stepped forward until the PN value received, and after update the new receiving chain is advanced to the message number just received, storing and expiring any message keys retrieved from each chain.

### Key expiration

Expired keys are kept for one hour, to allow re-decrypting received messages, espeacially in CLI operation, and to allow for Alice to decrypt the multiple initial replies that Bob may have sent. For skipped messages the chains are advanced and all skipped message keys are stored but immediately expired.

Unexpired temporary keys should have a longer expiration period such as four weeks, to avoid them being kept indefinitely if the conversation is never continued, or if an adversary is able to block all messages from being delivered.

All key expiration is strictly local. Covert files do not carry expiration timestamps. The actual implementation of expiration is covered by Covert idstore, to be documented in another document.


## Miscellaneus details

### Extensions

Single character dict keys are reserved to the format. Users may add custom metadata to any dict by using multi-letter key names.

The use of any unnecessary metadata, e.g. any names of programs used, is heavily discouraged.

### Ephemeral key hashing

A fresh ephemeral keypair is created for each Covert file. This is part of a standard ECDH exchange that makes up the public key system. The ephemeral public key is written to the file so that the recipient can, together with his secret key, decrypt the contents. The sender derives a shared key using the ephemeral secret key with the recipient public key and the immediately destroys the ephemeral key, so that he can no longer open the file.

A plain public key if stored in the header could be verified by outsiders as a valid key (with 25 % likelyhood of being just random data). Instead, Elligator2 hashing is used such that all bits are indistinguishable from random data. As per Elligator2, one needs to create random ephemeral keys until one that fits the encoding is found (half of attempts fail). Three additional random bits are needed in encoding, one for v coordinate sign that gets scrambled and stored in the hash, and two others to fill the otherwise zero high bits of Elligator2 output.

The receiver reverses this process, masking out the two high bit, then unhashing to recover the u coordinate (i.e. the ephemeral public key), while ignoring the v coordinate and its sign (Curve25519 never uses the v coordinate).

Depending on the sign bit two very distinct hashes as created, each in four variations by the other two bits in the final byte. Each of these eight possibilities should be produced equally likely, and each of them should be restored to identical bytes as the source key. Implementation of Elligator2 vary in their choice of the non-square value, making hashes incompatible. Covert uses value 2, while some implementations might be using sqrt(-1). Verify your code against the following test vectors:

```
# Ephemeral public key (Curve25519)
2b6a365dc67959894a00a9e07d45215bb8679ce1a47929bb643195e3adfc1755

# Possible ephash values (3 random bits give 8 possibilities)
04c158c70b275e02c0020add985ca2d9f712ea4eb702dac283d6931e689b391c
04c158c70b275e02c0020add985ca2d9f712ea4eb702dac283d6931e689b395c
04c158c70b275e02c0020add985ca2d9f712ea4eb702dac283d6931e689b399c
04c158c70b275e02c0020add985ca2d9f712ea4eb702dac283d6931e689b39dc
c914aa274bb2ebfadf735eab268417e8f292712d9c05fa399aee7972b99f1a00
c914aa274bb2ebfadf735eab268417e8f292712d9c05fa399aee7972b99f1a40
c914aa274bb2ebfadf735eab268417e8f292712d9c05fa399aee7972b99f1a80
c914aa274bb2ebfadf735eab268417e8f292712d9c05fa399aee7972b99f1ac0
```

The inverse hash should restore each of the variations to the exact same bytes as the original key.

### Endianess

All integers are unsigned and encoded in **little endian**, unless specified otherwise by foreign formats such as MsgPack (which is big endian).

### Character encoding

Text given as a message in terminal or other text input should be normalized by removing any trailing whitespace on each line. Lines must be terminated by LF only. There is no LF after the final line, all trailing newlines should be removed.

All Unicode, filenames and passwords in particular, must be normalized into **NFKC format**. Apple devices natively use NFD, which causes problems with passwords and filenames if not properly normalized. Strings extracted from Covert files should alike be transformed back to platform-native format as needed.

Finally, strings are always encoded in UTF-8 without BOM. Any text stored in MsgPack objects uses the string rather than the binary format.

### Real-time streaming

If the file length is not known in advance, no length is given in the index, and instead a MsgPack int object before each chunk tells how many bytes to read. Such a file is terminated by a MsgPack 0. Usually this occurs in a non-realtime context where the encoder may wait until a full block is done before sending it out.

The format also supports transmission of smaller blocks without delay. This requires coordination between the archive and the block layer regarding the next block lengths. It is recommended to choose a reasonably large next size (e.g. 1024) even if the data length is not known, and to fill any unused space with padding if needed, rather than to create 1-byte blocks with a huge overhead just to be safe.
