import sys
from concurrent.futures import ThreadPoolExecutor

from covert import idstore, passphrase, pubkey
from covert.cli import tty


def main_id(args):
  if len(args.files) > 1:
    raise ValueError("Argument error, one ID at most should be specified")
  if args.delete_entire_idstore:
    if args.files:
      raise ValueError("No ID should be provided with --delete-entire-idstore")
    try:
      idstore.delete_entire_idstore()
      sys.stderr.write(f"{idstore.idfilename} shredded and deleted.\n")
    except FileNotFoundError:
      sys.stderr.write(f"{idstore.idfilename} does not exist.\n")
    return
  if args.files:
    parts = args.files[0].split(":", 1)
    local = parts[0]
    peer = parts[1] if len(parts) == 2 else ""
    tagself = f"id:{local}"
    tagpeer = f"id:{local}:{peer}" if peer else None
  else:
    tagself = tagpeer = None
  if args.delete and not tagself:
    raise ValueError("Need an ID of form yourname or yourname:peername to delete.")
  # Load keys from command line
  selfkey = peerkey = None
  if args.recipients or args.recipfiles:
    if not tagpeer: raise ValueError("Need an ID of form yourname:peername to assign a public key")
    if len(args.recipients) + len(args.recipfiles) > 1: raise ValueError("Only one public key may be specified for ID store")
    peerkey = pubkey.decode_pk(args.recipients[0]) if args.recipients else pubkey.read_pk_file(args.recipfiles[0])[0]
  if args.identities:
    if not tagself: raise ValueError("Need an ID to assign a secret key.")
    if len(args.identities) > 1: raise ValueError("Only one secret key may be specified for ID store")
    selfkey = pubkey.read_sk_any(args.identities[0])[0]
  # First run UX
  create_idstore = not idstore.idfilename.exists()
  if create_idstore:
    if not tagself: raise ValueError("To create a new ID store, specify an ID to create e.g.\n  covert id alice\n")
    if tagpeer and not peerkey: raise ValueError(f"No public key provided for new peer {tagpeer}.")
    sys.stderr.write(f" 🗄️  Creating {idstore.idfilename}\n")
  # Passphrases
  idpass = newpass = None
  if not create_idstore:
    idpass = passphrase.ask("Master ID passphrase")[0]
  with ThreadPoolExecutor(max_workers=2) as executor:
    pwhasher = executor.submit(passphrase.pwhash, idpass) if idpass is not None else None
    newhasher = None
    if args.askpass or create_idstore:
      newpass, visible = passphrase.ask("New Master ID passphrase", create=5)
      newhasher = executor.submit(passphrase.pwhash, newpass)
      if visible:
        sys.stderr.write(f" 📝 Master ID passphrase: \x1B[32;1m{newpass.decode()}\x1B[0m\n")
    with tty.status("Password hashing... "):
      idhash = pwhasher.result() if pwhasher else None
      newhash = newhasher.result() if newhasher else None
    del idpass, newpass, pwhasher, newhasher
  # Update ID store
  for ids in idstore.update(idhash, new_pwhash=newhash):
    if args.delete:
      if tagpeer:
        del ids[tagpeer]
      else:
        # Delete ID and all peers connected to it
        del ids[tagself]
        for k in list(ids):
          if k.startswith(f"{tagself}:"): del ids[k]
      return
    # Update/add secret key?
    if tagself and tagself not in ids:
      ids[tagself] = dict()
      if not selfkey:
        sys.stderr.write(f" 🧑 {tagself} keypair created\n")
        selfkey = pubkey.Key()
    if selfkey:
      ids[tagself]["I"] = selfkey.sk
    # Update/add peer public key?
    if tagpeer and tagpeer not in ids:
      if not peerkey: raise ValueError(f"No public key provided for new peer {tagpeer}.")
      if tagpeer not in ids: ids[tagpeer] = dict()
      ids[tagpeer]["i"] = peerkey.pk
    # Print keys
    for key, value in ids.items():
      if tagself and key not in (tagself, tagpeer): continue
      if "I" in value:
        k = pubkey.Key(sk=value["I"])
        sk = pubkey.encode_age_sk(k)
        pk = pubkey.encode_age_pk(k)
        print(f"{key:15} {pk}")
        if args.secret: print(f" ╰─ {sk}")
      elif "i" in value:
        pk = pubkey.encode_age_pk(pubkey.Key(pk=value["i"]))
        print(f"{key:15} {pk}")
      # Ratchet info
      if (r := value.get("r")):
        state = "with forward secrecy" if r["RK"] else "initialising (messages sent but no response yet)"
        print(f"   conversation {state}")
