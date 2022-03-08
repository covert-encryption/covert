import mmap
import os
import sys
from concurrent.futures import ThreadPoolExecutor
from contextlib import suppress
from io import BytesIO
from pathlib import Path

import pyperclip
from nacl.exceptions import CryptoError
from tqdm import tqdm

from covert import idstore, lazyexec, passphrase, pubkey, util
from covert.archive import Archive
from covert.blockstream import BlockStream
from covert.cli import tty
from covert.util import ARMOR_MAX_SIZE, TTY_MAX_SIZE

idpwhash = None


def run_decryption(infile, args, b, idkeys):
  a = Archive()
  progress = None
  outdir = None
  f = None
  messages = []
  for data in a.decode(b.decrypt_blocks()):
    if isinstance(data, dict):
      # Header parsed, check the file list
      for i, infile in enumerate(a.flist):
        if infile.name is None:
          if infile.size is None or infile.size > TTY_MAX_SIZE:
            infile.name = f'noname.{i+1:03}'
            infile.renamed = True
        elif infile.name[0] == '.':
          infile.name = f"noname.{i+1:03}{infile['n']}"
          infile.renamed = True
      progress = tqdm(
        ncols=78,
        unit='B',
        unit_scale=True,
        total=a.total_size,
        bar_format="{l_bar}         {bar}{r_bar}",
        disable=a.total_size < 1 << 20
      )
    elif isinstance(data, bool):
      # Nextfile
      prev = a.prevfile
      if f:
        if isinstance(f, BytesIO):
          f.seek(0)
          data = f.read()
          try:
            messages.append(data.decode())
          except UnicodeDecodeError:
            pidx = a.flist.index(prev)
            prev.name = f"noname.{pidx + 1:03}"
            prev.renamed = True
            with get_writable_file(prev.name) as f2:
              f2.write(data)
        f.close()
        f = None
      if prev and prev.name is not None:
        r = '<renamed>' if prev.renamed else ''
        progress.write(f'{prev.size:15,d} 📄 {prev.name:60}{r}', file=sys.stderr)
      if a.curfile:
        n = a.curfile.name or ''
        if not n and a.curfile.size is not None and a.curfile.size < TTY_MAX_SIZE:
          f = BytesIO()
        elif args.outfile:
          if not outdir:
            outdir = Path(args.outfile).resolve()
            outdir.mkdir(parents=True, exist_ok=True)
            progress.write(f" ▶️ \x1B[1;34m  Extracting to \x1B[1;37m{outdir}\x1B[0m", file=sys.stderr)
          name = outdir.joinpath(n)
          if not name.resolve().is_relative_to(outdir) or name.is_reserved():
            progress.close()
            raise ValueError(f'Invalid filename {n!r}')
          name.parent.mkdir(parents=True, exist_ok=True)
          f = open(name, 'wb')
        elif outdir is None:
          outdir = False
          progress.write(
            " ▶️ \x1B[1;34m  The archive contains files. To extract, use \x1B[1;37m-o PATH\x1B[0m", file=sys.stderr
          )

      # Next file
      if progress:
        if a.fidx is not None:
          progress.set_description(f'{a.fidx + 1:03}/{len(a.flist):03}')
        else:
          progress.set_description('')
    else:
      if f:
        f.write(data)
      if progress:
        progress.update(len(data))
  if progress:
    progress.close()
  # Print any messages
  pretty = sys.stdout.isatty()
  for i, m in enumerate(messages):
    if pretty:
      sys.stderr.write("\x1B[1m 💬\n\x1B[1;34m")
      sys.stderr.flush()
      # Replace dangerous characters
      m = ''.join(c if c.isprintable() or c in ' \t\n' else f'\x1B[31m{repr(c)[1:-1]}\x1B[1;34m' for c in m)
    try:
      print(m)
    finally:
      if pretty:
        sys.stderr.write(f"\x1B[0m")
        sys.stderr.flush()
  # Print signatures
  b.verify_signatures(a)
  if b.header.authkey:
    sys.stderr.write(f" 🔑 Unlocked with {b.header.authkey}\n")
  elif b.header.ratchet:
    sys.stderr.write(f" 🔑 Conversation {b.header.ratchet.idkey}\n")
  sys.stderr.write(f' 🔷 File hash: {a.filehash[:12].hex()}\n')
  for valid, key, text in a.signatures:
    key = idkeys.get(key, key)
    if valid:
      sys.stderr.write(f" ✅ {text} {key}\n")
    else:
      sys.stderr.write(f"\x1B[1;31m ❌ {text} {key}\x1B[0m\n")
  # Start ratchet?
  if 'r' in a.index:
    if not args.idname:
      sys.stderr.write(f"You can start a conversation with forward secrecy by saving this contact:\n  covert dec --id yourname:theirname\n")
    else:
      global idpwhash
      if not idpwhash:
        idpwhash = passphrase.pwhash(passphrase.ask("Master ID passphrase")[0])
      idstore.save_contact(idpwhash, args.idname, a, b)

def main_dec(args):
  if len(args.files) > 1:
    raise ValueError("Only one input file is allowed when decrypting.")
  identities = {key for keystr in args.identities for key in pubkey.read_sk_any(keystr)}
  identities = list(sorted(identities, key=str))
  infile = open(args.files[0], "rb") if args.files else sys.stdin.buffer
  # If ASCII armored or TTY, read all input immediately (assumed to be short enough)

  # FIXME: For stdin the size is set to 50 so we try to read all of it (even if from a pipe),
  # so that armoring can work. But this breaks pipe streaming of large files that cannot
  # fit in RAM and tries to armor-decode very large files too. Needs to be fixed by
  # attempting to read some to determine whether the input is small enough, and if not,
  # use the covert.archive.CombinedIO object to consume the buffer already read and then
  # resume streaming.
  total_size = os.path.getsize(args.files[0]) if args.files else 50
  if infile.isatty():
    data = util.armor_decode(pyperclip.paste() if args.paste else tty.read_hidden("Encrypted message"))
    if not data:
      raise KeyboardInterrupt
    infile = BytesIO(data)
    total_size = len(data)
    del data
  elif 40 <= total_size <= 2 * ARMOR_MAX_SIZE:
    # Try reading the file as armored text rather than binary
    with infile:
      data = infile.read()
    try:
      infile = BytesIO(util.armor_decode(data.decode()))
    except Exception:
      infile = BytesIO(data)
  else:
    with suppress(OSError):
      infile = mmap.mmap(infile.fileno(), 0, access=mmap.ACCESS_READ)
  b = BlockStream()
  with b.decrypt_init(infile):
    idkeys = {}
    # Authenticate
    with ThreadPoolExecutor(max_workers=4) as executor:
      pwhasher = lazyexec.map(executor, passphrase.pwhash, {util.encode(pwd) for pwd in args.passwords})
      def authgen():
        nonlocal idkeys
        yield from identities
        e = None
        with tty.status("Password hashing... "):
          yield from pwhasher
          if not args.askpass and idstore.idfilename.exists():
            global idpwhash
            idpwhash = None  # In case main_dec is run multiple times (happens in tests)
            try:
              idpwhash = passphrase.pwhash(passphrase.ask("Master ID passphrase")[0])
              idkeys = idstore.idkeys(idpwhash)
              yield from idstore.authgen(idpwhash)
            except ValueError as e:
              # Treating as error only when suitable passphrase was given
              if idpwhash: raise ValueError(f"ID store: {e}")
          # Ask for passphrase if asked for or if no other methods were attempted
          if args.askpass or not (args.passwords or args.identities):
            yield passphrase.pwhash(passphrase.ask('Passphrase')[0])
      if not b.header.key:
        auth = authgen()
        for a in auth:
          with suppress(CryptoError):
            b.authenticate(a)
            break
        auth.close()
    # Decrypt and verify
    run_decryption(infile, args, b, idkeys)
