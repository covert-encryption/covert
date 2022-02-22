from covert.ratchet import Ratchet
from covert.pubkey import Key

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
