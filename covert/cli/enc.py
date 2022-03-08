import os
import sys
from concurrent.futures import ThreadPoolExecutor
from io import BytesIO

import pyperclip
from tqdm import tqdm

from covert import idstore, passphrase, pubkey, util
from covert.archive import Archive
from covert.blockstream import encrypt_file
from covert.cli import tty
from covert.util import ARMOR_MAX_SIZE, TTY_MAX_SIZE


def main_enc(args):
  padding = .01 * float(args.padding) if args.padding is not None else .05
  if not 0 <= padding <= 3.0:
    raise ValueError('Invalid padding specified. The valid range is 0 to 300 %.')
  # Passphrase encryption by default if no auth is specified
  if not (args.idname or args.askpass or args.passwords or args.recipients or args.recipfiles or args.wideopen):
    args.askpass = 1
  # Convert recipient definitions into keys
  recipients = []
  for keystr in args.recipients:
    try:
      recipients.append(pubkey.decode_pk(keystr))
    except ValueError as e:
      if keystr.startswith("github:"):
        raise ValueError(f"Unrecognized recipient string. Download a key from Github by -R {keystr}")
      elif os.path.isfile(keystr):
        raise ValueError(f"Unrecognized recipient string. Use a keyfile by -R {keystr}")
      raise
  for fn in args.recipfiles:
    recipients += pubkey.read_pk_file(fn)
  # Unique recipient keys sorted by keystr
  l = len(recipients)
  recipients = list(sorted(set(recipients), key=str))
  if len(recipients) < l:
    sys.stderr.write(' ⚠️ Duplicate recipient keys dropped.\n')
  if args.idname and len(recipients) > 1:
    raise ValueError("Only one recipient may be specified for ID store.")
  # Signatures
  signatures = {key for keystr in args.identities for key in pubkey.read_sk_any(keystr) if key.edsk}
  signatures = list(sorted(signatures, key=str))
  if args.idname and len(signatures) > 1:
    raise ValueError("Only one secret key may be specified for ID store.")
  # Ask passphrases
  if args.idname:
    if len(signatures) > 1: raise ValueError("Only one secret key may be associated with an identity.")
    if len(recipients) > 1: raise ValueError("Only one recipient key may be associated with an identity.")
    if idstore.idfilename.exists():
      idpass, _ = passphrase.ask("Master ID passphrase")
    else:
      idpass = util.encode(passphrase.generate(5))
      sys.stderr.write(f" 🗄️  Master ID passphrase: \x1B[32;1m{idpass.decode()}\x1B[0m (creating {idstore.idfilename})\n")
  numpasswd = args.askpass + len(args.passwords)
  passwords, vispw = [], []
  for i in range(args.askpass):
    num = f" {i+1}/{numpasswd}" if numpasswd > 1 else ""
    pw, visible = passphrase.ask(f"New passphrase{num}", create=True)
    passwords.append(pw)
    if visible:
      vispw.append(pw.decode())
    del pw
  passwords += map(util.encode, args.passwords)
  # Use threaded password hashing for parallel and background operation
  with ThreadPoolExecutor(max_workers=4) as executor:
    if args.idname:
      idpwhasher = executor.submit(passphrase.pwhash, idpass)
      del idpass
    pwhasher = executor.map(passphrase.pwhash, set(passwords))
    # Input files
    if not args.files or True in args.files:
      if sys.stdin.isatty():
        data = tty.editor()
        # Prune surrounding whitespace
        data = '\n'.join([l.rstrip() for l in data.split('\n')]).strip('\n')
        stin = util.encode(data)
      else:
        stin = sys.stdin.buffer
      args.files = [stin] + [f for f in args.files if f != True]
    # Collect the password hashing results
    pwhashes = set()
    if args.idname or passwords:
      with tty.status("Password hashing... "):
        if args.idname: idpwhash = idpwhasher.result()
        pwhashes = set(pwhasher)
      del passwords
    # ID store update
    ratch = None
    if args.idname:
      # Try until the passphrase works
      while True:
        try:
          idkey, peerkey, ratch = idstore.profile(
            idpwhash,
            args.idname,
            idkey=signatures[0] if signatures else None,
            peerkey=recipients[0] if recipients else None,
          )
          break
        except ValueError as e:
          # TODO: Add different exception types to avoid this check
          if "Not authenticated" not in str(e): raise
        idpwhash = passphrase.pwhash(passphrase.ask("Wrong password, try again. Master ID passphrase")[0])
      signatures = [idkey]
      recipients = [peerkey]
  # Prepare for encryption
  a = Archive()
  a.file_index(args.files)
  if ratch:
    if ratch.RK:
      # Enable ratchet mode auth
      recipients = ratch
    else:
      # Advertise ratchet capability and send initial message number
      a.index['r'] = ratch.s.N
  if signatures:
    a.index['s'] = [s.pk for s in signatures]
  # Output files
  realoutf = open(args.outfile, "wb") if args.outfile else sys.stdout.buffer
  if args.armor or not args.outfile and sys.stdout.isatty():
    if a.total_size > (ARMOR_MAX_SIZE if args.outfile else TTY_MAX_SIZE):
      if not args.outfile:
        raise ValueError("Too much data for console. How about -o FILE to write a file?")
      raise ValueError("The data is too large for --armor.")
    outf = BytesIO()
  else:
    outf = realoutf
  # Print files during encoding and update padding size at the end
  def nextfile_callback(prev, cur):
    if prev:
      s, n = prev.size, prev.name
      progress.write(f'{s:15,d} 📄 {n:60}' if n else f'{s:15,d} 💬 <message>', file=sys.stderr)
    if not cur:
      a.random_padding(padding)
      progress.write(f'\x1B[1;30m{a.padding:15,d} ⬛ <padding>\x1B[0m', file=sys.stderr)

  a.nextfilecb = nextfile_callback
  # Main processing
  with tqdm(
    total=a.total_size, delay=1.0, ncols=78, unit='B', unit_scale=True, bar_format="{l_bar}         {bar}{r_bar}"
  ) as progress:
    for block in encrypt_file((args.wideopen, pwhashes, recipients, signatures), a.encode, a):
      progress.update(len(block))
      outf.write(block)
  # Store ratchet
  if ratch: idstore.update_ratchet(idpwhash, ratch, a)
  # Pretty output printout
  if sys.stderr.isatty():
    # Print a list of files
    lock = " 🔓 wide-open" if args.wideopen else " 🔒 covert"
    if ratch and ratch.RK:
      methods = f'🔗 #{ratch.s.CN + ratch.s.N}'
    else:
      methods = "  ".join(
        [f"🔗 {r}" for r in recipients] + [f"🔑 {a}" for a in vispw] + (numpasswd - len(vispw)) * ["🔑 <pw>"]
      )
      methods += f' 🔷 {a.filehash[:12].hex()}'
    for s in signatures:
      methods += f"  🖋️ {s}"
    if methods:
      lock += f"    {methods}"
    if args.outfile:
      lock += f"  💾 {args.outfile}\n"
    elif args.paste:
      lock += f"  📋 copied\n"
    out = f"\n\x1B[1m{lock}\x1B[0m\n"
    sys.stderr.write(out)
    sys.stderr.flush()
  if outf is not realoutf:
    outf.seek(0)
    data = outf.read()
    data = util.armor_encode(data)
  if outf is not realoutf:
    if args.paste:
      pyperclip.copy(f"```\n{data}\n```\n")
      return
    pretty = realoutf.isatty()
    if pretty:
      sys.stderr.write("\x1B[1;30m```\x1B[0;34m\n")
      sys.stderr.flush()
    try:
      realoutf.write(f"{data}\n".encode())
      realoutf.flush()
    finally:
      if pretty:
        sys.stderr.write("\x1B[1;30m```\x1B[0m\n")
        sys.stderr.flush()
  # Not using `with outf` because closing stdout causes a lot of trouble and
  # missing the close on a file when the CLI exits anyway is not dangerous.
  # TODO: Delete the output file if any exception occurs.
  if outf is not sys.stdout.buffer:
    outf.close()
