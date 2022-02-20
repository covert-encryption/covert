from covert.ratchet import Ratchet
from covert.pubkey import Key

def test_ratchet_pubkey():
  alice = Key()
  bob = Key()
  a = Ratchet()
  a.init_alice(alice, bob)
  header, mka = a.send(bob)

  b = Ratchet()
  b.init_bob(bob, alice)
  mkb = b.receive(header)

  assert mka == mkb
