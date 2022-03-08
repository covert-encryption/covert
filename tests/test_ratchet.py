from copy import deepcopy
from secrets import token_bytes

import pytest
from nacl.exceptions import CryptoError

from covert.idstore import remove_expired
from covert.pubkey import Key
from covert.ratchet import Ratchet


def test_ratchet_pubkey():
  alice = Key()
  bob = Key()
  a = Ratchet()
  shared = token_bytes()
  a.peerkey = bob
  a.prepare_alice(shared, alice)

  b = Ratchet()
  b.init_bob(shared, bob, alice)

  header1, mkb = b.send()
  mka = a.receive(header1)

  assert mka == mkb
  assert b.s.N == 1
  assert a.r.N == 1
  assert b.s.HK
  assert b.s.HK == a.r.HK

  header2, mkb2 = b.send()
  assert mkb2 != mkb

  header3, mkb3 = b.send()
  assert mkb3 != mkb2

  # Receive out of order
  mka3 = a.receive(header3)
  assert mka3 == mkb3

  mka2 = a.receive(header2)
  assert mka2 == mkb2

  # Send and receive on current chain (no roundtrip)
  header4, mkb4 = b.send()
  header5, mkb5 = b.send()
  header6, mkb6 = b.send()
  mka5 = a.receive(header5)
  assert mka5 == mkb5
  mka6 = a.receive(header6)
  assert mka6 == mkb6


def test_ratchet_lost_messages():
  alice = Key()
  bob = Key()
  a = Ratchet()
  shared = [token_bytes(32) for i in range(3)]
  a.peerkey = bob
  a.prepare_alice(shared[0], alice)
  a.prepare_alice(shared[1], alice)
  a.prepare_alice(shared[2], alice)
  assert a.s.N == 3
  assert a.pre == shared

  b = Ratchet()
  b.init_bob(shared[1], bob, alice)

  header1, mkb1 = b.send()
  header2, mkb2 = b.send()
  header3, mkb3 = b.send()

  assert b.s.HK in a.pre
  assert b.s.N == 3

  mka2 = a.receive(header2)

  assert mka2 == mkb2
  assert a.r.N == 2

  header4, mkb4 = b.send()
  assert b.s.N == 4

  mka4 = a.receive(header4)
  assert mka4 == mkb4
  assert a.r.N == 4

  # Receive out of order
  mka3 = a.receive(header3)
  assert mka3 == mkb3

  # Receive out of order
  mka1 = a.receive(header1)
  assert mka1 == mkb1

  # Fail to decode own message
  with pytest.raises(CryptoError):
    b.receive(header1)


def test_expiration(mocker):
  soon = 600
  later = 86400 * 28
  mocker.patch("time.time", return_value=1e9)
  r = Ratchet()
  assert r.e == 1_000_000_000 + later

  r.init_bob(bytes(32), Key(), Key())
  r.readmsg()
  assert r.msg[0]["e"] == 1_000_000_000 + soon

  ids = {
    "id:alice": {"I": bytes(32)},
    "id:alice:bob": {
      "i": bytes(32),
      "e": 2_000_000_000,
      "r": r.store(),
    },
  }

  ids2 = deepcopy(ids)
  remove_expired(ids2)
  assert ids == ids2

  mocker.patch("time.time", return_value=1e9 + soon + 1)
  ids2 = deepcopy(ids)
  remove_expired(ids2)
  assert not ids2["id:alice:bob"]["r"]["msg"]

  mocker.patch("time.time", return_value=1e9 + later + 1)
  ids2 = deepcopy(ids)
  remove_expired(ids2)
  assert not "r" in ids2["id:alice:bob"]

  mocker.patch("time.time", return_value=2e9 + 1)
  ids2 = deepcopy(ids)
  remove_expired(ids2)
  assert not "id:alice:bob" in ids2
