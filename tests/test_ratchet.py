import pytest
from nacl.exceptions import CryptoError

from covert.pubkey import Key
from covert.ratchet import Ratchet


def test_ratchet_pubkey():
  alice = Key()
  bob = Key()
  a = Ratchet()
  a.init_alice(alice, bob)
  header, mka = a.send(bob)
  assert len(header) == 83
  assert mka
  assert a.Ns == 1
  assert not a.skipped
  assert not a.h_send
  assert a.nh_send

  b = Ratchet()
  mkb = b.init_bob(bob, header)
  assert mka == mkb
  assert b.Nr == 1
  assert not b.skipped
  assert b.h_send
  assert b.h_send == a.nh_recv

  header2, mkb2 = b.send()
  assert mkb2 != mkb

  header3, mkb3 = b.send()
  assert mkb3 != mkb2

  # Receive out of order
  mka3 = a.receive(header3)
  assert mka3 == mkb3

  mka2 = a.receive(header2)
  assert mka2 == mkb2


def test_ratchet_lost_messages():
  alice = Key()
  bob = Key()
  a = Ratchet()
  a.init_alice(alice, bob)
  header0, mka0 = a.send(bob)
  header1, mka1 = a.send(bob)
  header2, mka2 = a.send(bob)
  assert a.Ns == 3

  b = Ratchet()
  mkb1 = b.init_bob(bob, header1)
  assert mka1 == mkb1
  assert b.Nr == 2
  assert len(b.skipped) == 1

  header3, mkb3 = b.send()
  header4, mkb4 = b.send()
  assert b.Ns == 2

  mka4 = a.receive(header4)
  assert mka4 == mkb4
  assert a.Nr == 2
  assert len(a.skipped) == 1

  # Receive out of order
  mka3 = a.receive(header3)
  assert mka3 == mkb3
  assert not a.skipped

  # Receive out of order
  mkb0 = b.receive(header0)
  assert mka0 == mkb0

  # Fail to decode own message
  with pytest.raises(CryptoError):
    a.receive(header0)
