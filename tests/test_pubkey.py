from hashlib import sha512
from secrets import token_bytes

import nacl.bindings as sodium

from covert import pubkey
import pytest


# Test vectors from https://age-encryption.org/v1
AGE_PK = "age1zvkyg2lqzraa2lnjvqej32nkuu0ues2s82hzrye869xeexvn73equnujwj"
AGE_SK = "AGE-SECRET-KEY-1GFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPQ4EGAEX"
AGE_SK_BYTES = 32 * b"\x42"


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


def test_ssh_key_decoding():
  pk, = pubkey.read_pk_file("tests/keys/ssh_ed25519.pub")
  sk, = pubkey.read_sk_file("tests/keys/ssh_ed25519")
  assert pk.comment == "test-key@covert"
  assert sk.comment == "test-key@covert"
  assert pk == sk


def test_ssh_pw_keyfile(mocker):
  mocker.patch('covert.passphrase.ask', return_value=(b"password", True))
  sk, = pubkey.read_sk_file("tests/keys/ssh_ed25519_password")
  assert sk.comment == "password-key@covert"


def test_ssh_wrong_password(mocker):
  mocker.patch('covert.passphrase.ask', return_value=(b"not this password", True))
  with pytest.raises(ValueError):
    sk, = pubkey.read_sk_file("tests/keys/ssh_ed25519_password")


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
