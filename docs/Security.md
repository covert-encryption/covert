# Covert Encryption Security

## Anonymity and deniability matter

A practical concern is when you end up in court and the prosecutor shows a file obtained from your drive. Just holding something saying `PGP ENCRYPTED MESSAGE` could get you convicted in Iran or China. Even in the UK refusing to hand over the keys can get you convicted. Even worse, if a header shows that the message was addressed to a public key of a known enemy of the state such as Edward Snowden... However, if all the prosecuter has is a blob of random data, it is hard to make a case (assuming the filename itself is not revealing). This is deniability.

Another kind of deniability occurs when a recipient of a message takes its contents and claims that you are responsible for something within. This is the type that Signal touts with their protocol, as the receiver could easily forge message contents (still identifying you as the sender). How effective this is depends on who is doing the claim and whom the message benefits, as generally speaking it is quite unplausible that a receiver would forge a message addressed to him.

Covert avoids the Signal type of deniability because by default messages carry no sender identification at all. If the sender wishes to identify, a signature is also added, making forgery impossible.

The lack of any identifiable bits is also necessary for applying steganographic methods to hide the encrypted file within photographs, movie files or elsewhere, where any identifiable sequence could easily defeat the encoding. While staganographic encoding is outside the scope of this project, we wish to support such usage.

PGP (by default) and Age add plain text recipient key IDs to messages, allowing anyone to see if the message was addressed to a specific key. If two parties exchange messages over an otherwise anonymous medium (e.g. a Tor message board), anyone who sees those messages can determine who the participants are (provided that their public keys are public). We believe that not even legitimate recipients should know who else the message was addressed to.

## A note on forward secrecy

Secret keys get compromised. USB keys get lost, computers get hacked or confiscated, and people can be coerced to give their keys and passwords. It happens eventually, if not to you, then to someone you were communicating with.

Forward secrecy means that messages sent and received earlier can not be opened even if the keys are leaked. This is accomplished by regularly switching to new keys and disposing of the old ones.

We believe that forward secrecy is very important, but it is also difficult to implement as an offline protocol. As of now, Covert messages can be opened by any recipient secret key that still exists. Covert does not implement its own key management but relies on other public key systems, none of which provide good key exchange mechanisms, so the same keys are likely kept and used for a long time.

In other words, we are right where PGP is, and this is unacceptable. We need a system where publicly available long term keys are combined with short term keys, providing forward secrecy. It is a difficult problem to solve for offline messaging, so this remains an open question, although with a help of a keyserver schemes such as [X3DH](https://signal.org/docs/specifications/x3dh/) it is possible to protect any initial message. Reply messages could be protected even while keeping the initiator party anonymous, if the sender embdded a short term reply key that the other party can use to send back a response or a series of responses, but that gets deleted (and updated) as soon as a reply is received. This of course requires also some state information stored in an encrypted identity file on local system, for maintaining the short term keys.

Any input on this field would be particularly welcome!

## Yubikeys

There is limited support for encryption on these devices. Age already implements a plugin but that can only use identities generated in Age, not existing keys.

## Thread analysis

The security model considers two threat vectors separately. An *outsider* does not have the keys required to decrypt the file but that has full knowledge of everything else, including possible plain texts, and an ability to manipulate the ciphertext. An *insider* who is one of the recipients. Both know all possible recipient public keys.

The sender of a message becomes an outsider, unable to open his own own message, unless he is also a recipient.

### Outsiders

* Impossible to determine with any confidence that a file is Covert encrypted and not just random data
  - There are no identifiable headers, checksums, fields or values that could be verified without valid keys
  - File sizes are not padded to known lengths but can be of any byte lengths above that required for the content.
* Impossible to manipulate the encrypted data in any way without being detected
  - Headers, structures and all data are protected by Poly1305 authentication tags
  - Truncating the file at any position causes decryption error
  - Timing and decryption oracle attacks are limited
* Impossible to determine among plain texts of similar length which plain text is contained
  - Random padding is used to produce files of any byte-length above what is required by the content
  - The randomly chosen padding is clamped so that very short messages are padded to certain minimum length

All other major encryption formats add headers that expose the content. Protocols such as Tor use their unique fixed block sizes, which are easily identified. Most padding schemes also suffer of this, and unless randomness is used, two distinct sizes are produced for plain texts above and below the boundary.

The Base64 encoded format lessens the first guarantee, as one might identify the specific dialect of Base64 being used, or the length that lines are split to. While binary files should be preferred when ASCII armoring is not required, the armoring used (url-safe base64 w/o padding) is common enough such that no confidence on it being Covert encrypted can be asserted.

### Insiders

* Impossible to identify other recipients
  - A recipient can only determine the maximum number of recipients that there may be
  - No way to determine whether other slots are for passwords, keys or just random filler
* Any recipient can forge file contents, keeping the same recipients
  - Signal calls this Deniability, although it is a very weak kind of that
  - Data modification keeping the same header is unsafe and is not supported by our tools
* Anything in signed files cannot be modified without detection
  - Can only rewrite the file without any signature

## Potentially revealing fields

### Public key

The header field `ephash` is scrambled because a plain ephemeral public key could be verified as a valid curve element, with significant confidence if several files were inspected. In plain keys the highest bit is always zero and only half of the remaining values are used. [Elligator2 hashing](https://www.shiftleft.org/papers/elligator/elligator.pdf) is used on this field. Normal Curve25519 keys leave two bits of entropy unused but since Elligator2 rejects half of otherwise possible keys, there are three bits to fill. One is a sign bit, unused in Curve25519 schemes but still encoded (and scrambled) in Elligator2. The resulting hash still leaves the two highest bits zeroes. These three bits could be used to carry information, in particular the sign bits of Ed25519 keys, e.g. the sign bits of randomly generated Ed25519 keys. Covert has no use for any such data, and uses secure random bits instead, making the ephemeral key hash indistinguishable from random data.

It is also important that the key is under no circumstances known to outsiders, as comparing with a known public key would reveal file contents. Ephemeral keys are randomly generated each time that something is encrypted, so we can be sure of having random-looking bits to start with and of never reusing the same bits anywhere else.

### Auth fields

Auth keys for passwords are produced by Argon2, which uses Blake2b hashing to produce its output, and this should by design be unrecognizable. The output is also always different even for the same password, provided that the 12 bytes of nonce in hash calculation are different. Auth keys for public keys are truncated SHA-512 hashes of generated shared ECDH secrets. The shared secret and the auth key are always different depending on the 

Care must be taken in implementation of encryption not to include same auth method twice if the same password or the same public key was specified multiple times, as doing so could defeat all security (if one of the duplicates became the file key and the other appeared as an all-zero auth token), or at least cause duplicated strings to appear in header.

### ChaCha20 encrypted data

The cipher xors the plaintext with a securely random stream of bytes, thus any ciphertext produced is also indistinguishable from random bytes.

### Poly1305 tags

The checksum tag locations in ciphertext are easily guessed if the standard encoder is used. The checksum is calculated from ciphertext, but with an initial seeding block extracted from the ChaCha20 cipher, thus making verification by ciphertext only impossible. All 16-byte values of output should also be equally likely, providing for random-lookingness.

## Confidence on security

Covert is based on standard key derivation algorithms Argon2, ECHD and SHA-512, and an authenticated block cipher ChaCha20-Poly1305, all believed to be secure. Still, implementation details around those matter, and Covert does some unordinary choices to save space.

### Random numbers

The quality of random numbers is paramount and the most common flaw causing breakage of cryptosystems. The standard implementation uses Python's `secrets` module, which promises to provide cryptographically secure numbers, which apparently means calling OS functions roughly equivalent to `/dev/random` on Linux. This is believed to be secure, although some platform that Python runs on could offer a significantly less good random data source.

Implementations must never use C `rand()` or other such functions that are in no way cryptographically secure. Additionally, for seeding or for all generation, OS secure random functions need to be used, and any generator used must have large internal state (anything that seeds with an integer is not good, and forget about using the current time as seed).

The amount of random numbers needed in Covert is very minimal.

### Nonce reuse

Covert uses the same nonce for hashing passwords, hashing pubkey tokens and for encryption of Block0. Additionally, the nonce shares bytes with ephpk, also used in generation of those pubkey tokens.

A nonce must never be reused with the same key and the same algorithm.

Further the nonce must be random enough so that it never reappears. Provided that the ephpk uses most of the information available within its 32 bytes to actually provide 256 bits of security, the first 12 bytes should be decently random, enough to avoid any collisions (12 bytes is more than enough for that).

### XOR of auth keys

Xorring plaintext with secure bytes to obtain ciphertext is a common practice used in modern block cipher modes (AES-CTR/GCM, ChaCha20) but the security of this generally relies on that the secure bytes are always different (i.e. nonces must not be reused with the same key), and that the data is separately authenticated (otherwise flipping a bit in ciphertext flips the same bit on plaintext, leading to attacks when the plaintext can be guessed).

Since any modification of the header is guaranteed to fail file decryption, the authentication part is covered.

All auth keys are assumed to be secure bytes because they are produced by local hashing based on locally created randomness, so an outsider could not affect which keys are created e.g. by careful choice of public keys used as recipients. However, we need a further requirement that the keys are independent, or otherwise they are not secure bytes. This is not the case if the same password or the same public key is used many times encrypting a file, as then all parameters used in hashing are identical and identical keys are produced. Then key0 ⊕ key1 is all zeroes. If the same key appeared twice and there were also other recipients, two identical auth slots could appear (rather than one of full zeroes) depending on whether that same or some other key ended up as the file key. Any of these would immediately cause the header to be recognizable, even though the file itself cannot be opened without knowing the keys.

For multiple recipients, several auth keys are xorred with the same file key. Is this a problem? If the original keys look like random data, xorring all of them does not make them look any less random. The holder of any of keys can learn the file key and subsequently all the other keys used, but that does not provide him any information. Not even whether the keys are from public keys, passwords or just dummy random entries.

### Blindly finding Block0

For a single authentication method, 20 potential file keys must be attempted for all possible Block0 starting offset and ending offsets. In the worst case this gives 124212 decryption attempts, all of which are expected to fail if the correct key is not known. This amounts to 17 bits against the 128 bits of Poly1305. Thus, 111 bits remain, meaning that it is impossible to find a wrong combination that fits.

Although it may seem expensive, performance-wise the search is really not an issue. All those trials take a fraction of a second, and if needed, the number of combinations can be cut drastically if the block is assumed to end at EOF or offset 1024 (as it normally is), rather than trying every possible length, at least before performing the full search. We also expect no significant side channel leak of this search over that of a normal run of the cipher over a large file.