from hashlib import sha512
from secrets import token_bytes

import nacl.bindings as sodium

from covert import pubkey
import pytest


# Test vectors from https://age-encryption.org/v1
AGE_PK = "age1zvkyg2lqzraa2lnjvqej32nkuu0ues2s82hzrye869xeexvn73equnujwj"
AGE_SK = "AGE-SECRET-KEY-1GFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPQ4EGAEX"
AGE_SK_BYTES = 32 * b"\x42"

# Generated with wg genkey and wg pubkey
WG_SK = "kLkIpWh5MYKwUA7JdQHnmbc6dEiW0py4VRvqmYyPLHc="
WG_PK = "ElMfFd2qVIROK4mRaXJouYWC2lxxMApMSe9KyAZcEBc="


def test_age_key_decoding():
  pk = pubkey.decode_pk(AGE_PK)
  sk = pubkey.decode_sk(AGE_SK)
  # Key comparison is by public keys
  assert pk == sk
  assert pk.keystr == AGE_PK
  assert sk.keystr == AGE_SK
  assert pk.comment == 'age'
  assert sk.comment == 'age'
  assert repr(pk).endswith(':PK]')
  assert repr(sk).endswith(':SK]')


def test_age_key_decoding_and_encoding():
  pk = pubkey.decode_age_pk(AGE_PK)
  sk = pubkey.decode_age_sk(AGE_SK)
  assert pk == pubkey.decode_pk(AGE_PK)
  assert sk == pubkey.decode_sk(AGE_SK)
  assert pubkey.encode_age_pk(pk) == AGE_PK
  assert pubkey.encode_age_pk(sk) == AGE_PK
  assert pubkey.encode_age_sk(sk) == AGE_SK


def test_wireguard_keystr():
  pk = pubkey.decode_pk(WG_PK)
  sk = pubkey.decode_sk(WG_SK)
  # Key comparison is by public keys
  assert pk == sk
  assert pk.keystr == WG_PK
  assert sk.keystr == WG_SK
  assert pk.comment == 'wg'
  assert sk.comment == 'wg'
  assert repr(pk).endswith(':PK]')
  assert repr(sk).endswith(':SK]')

  # Trying to decode a public key as secret key should usually fail
  # (works with the test key but no guarantees with others)
  with pytest.raises(ValueError) as exc:
    pubkey.decode_sk(WG_PK)
  assert "Unable to parse secret key" in str(exc.value)


def test_ssh_key_decoding():
  pk, = pubkey.read_pk_file("tests/keys/ssh_ed25519.pub")
  sk, = pubkey.read_sk_file("tests/keys/ssh_ed25519")
  assert pk.comment == "test-key@covert"
  assert sk.comment == "test-key@covert"
  assert pk == sk


def test_file_not_found():
  with pytest.raises(ValueError) as exc:
    pk, = pubkey.read_pk_file("tests/keys/non-existent-file.pub")
  assert "Keyfile" in str(exc.value)

  with pytest.raises(ValueError) as exc:
    sk, = pubkey.read_sk_file("tests/keys/non-existent-file")
  assert "Secret key file" in str(exc.value)


def test_ssh_pw_keyfile(mocker):
  mocker.patch('covert.passphrase.ask', return_value=(b"password", True))
  sk, = pubkey.read_sk_file("tests/keys/ssh_ed25519_password")
  assert sk.comment == "password-key@covert"


def test_ssh_wrong_password(mocker):
  mocker.patch('covert.passphrase.ask', return_value=(b"not this password", True))
  with pytest.raises(ValueError):
    sk, = pubkey.read_sk_file("tests/keys/ssh_ed25519_password")


def test_minisign_keyfiles(mocker):
  mocker.patch('covert.passphrase.ask', return_value=(b"password", True))
  sk, = pubkey.read_sk_file("tests/keys/minisign_password.key")
  pk, = pubkey.read_pk_file("tests/keys/minisign_password.pub")
  assert sk.comment == 'ms'
  assert pk.comment == 'ms'
  assert sk == pk


def test_key_exchange():
  # Alice sends a message to Bob
  nonce = token_bytes(12)
  eph_pk, eph_sk = sodium.crypto_kx_keypair()
  assert len(eph_pk) == 32
  assert len(eph_sk) == 32
  bob = pubkey.Key()
  eph = pubkey.Key(sk=eph_sk)
  alice_key = pubkey.derive_symkey(nonce, eph, bob)
  # Bob receives the message (including nonce and eph_pk)
  eph = pubkey.Key(pk=eph_pk)
  bob_key = pubkey.derive_symkey(nonce, bob, eph)
  assert alice_key == bob_key
