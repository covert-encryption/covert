import itertools
import mmap
import os
import sys
from concurrent.futures import ThreadPoolExecutor
from contextlib import suppress
from io import BytesIO
from pathlib import Path
from time import perf_counter

import pyperclip
from nacl.exceptions import CryptoError
from tqdm import tqdm

from covert import idstore, lazyexec, passphrase, pubkey, tty, util
from covert.archive import Archive, FileRecord
from covert.blockstream import BlockStream, decrypt_file, encrypt_file
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


def main_dec(args):
  if len(args.files) > 1:
    raise ValueError("Only one input file is allowed when decrypting.")
  # Ask for passphrase by default if no auth is specified
  if not (args.askpass or args.passwords or args.identities):
    args.askpass = 1
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
        with tty.status("Password hashing... "):
          yield from pwhasher
          if idstore.idfilename.exists():
            global idpwhash
            idpwhash = passphrase.pwhash(passphrase.ask("Master ID passphrase")[0])
            idkeys = idstore.idkeys(idpwhash)
            yield from idstore.authgen(idpwhash)
          for i in range(args.askpass):
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


def main_edit(args):
  if len(args.files) != 1:
    raise ValueError("Edit mode requires an encrypted archive filename (or '-' to use stdio).")
  fname = args.files[0]
  # Read all of input file (or stdin) to RAM
  if fname is True:
    data = sys.stdin.buffer.read()
  else:
    with open(fname, "rb") as f:
      data = f.read()
  try:
    infile = BytesIO(util.armor_decode(data.decode()))
    args.armor = True
  except Exception:
    infile = BytesIO(data)
  # Decrypt everything to RAM
  pwhash = passphrase.pwhash(passphrase.ask("Passphrase")[0])
  a = Archive()
  for data in a.decode(decrypt_file([pwhash], infile, a)):
    if isinstance(data, dict): pass
    elif isinstance(data, bool):
      if data: a.curfile.data = bytearray()
    else: a.curfile.data += data
  # Edit the message (should be the first file)
  if a.flist and a.flist[0].name is None:
    a.flist[0].data = util.encode(tty.editor(a.flist[0].data.decode()))
    a.flist[0].size = len(a.flist[0].data)
  else:
    data = util.encode(tty.editor())
    a.flist.insert(0, FileRecord([len(data), None, {}]))
    a.flist[0].data = data
  # Reset archive for re-use in encryption
  a.reset()
  a.fds = [BytesIO(f.data) for f in a.flist]
  a.random_padding()
  # Encrypt in RAM...
  out = bytearray()
  for block in encrypt_file((False, [pwhash], [], []), a.encode, a):
    out += block
  # Preserve armoring if the input was armored
  if args.armor:
    out = f"{util.armor_encode(out)}\n".encode()
  # Finally write output / replace the file
  if fname is True:
    sys.stdout.buffer.write(out)
  else:
    with open(fname, "wb") as f:
      f.write(out)


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
    if len(args.recipients) + len(args.recipfiles) > 1: raise ValueError("Only one public be specified for ID store")
    peerkey = pubkey.decode_pk(args.recipients[0]) if args.recipients else pubkey.read_pk_file(args.recipfiles[0])[0]
  if args.identities:
    if not tagself: raise ValueError("Need an ID to assign a secret key.")
    if len(args.identities) > 1: raise ValueError("Only one secret key may be specified for ID store")
    peerkey = pubkey.read_sk_any(args.identities[0])
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


def main_benchmark(args):

  def noop_read(block):
    nonlocal dataleft
    block.pos = min(block.spaceleft, dataleft)
    dataleft -= block.pos

  datasize = int(1e9)
  a = Archive()

  # Count ciphertext size and preallocate mmapped memory
  dataleft = datasize
  size = sum(len(block) for block in encrypt_file((True, [], [], []), noop_read, a))
  ciphertext = mmap.mmap(-1, size)
  ciphertext[:] = bytes(size)

  rounds = 3
  enctotal = dectotal = 0
  for i in range(rounds):
    print("ENC", end="", flush=True)
    dataleft, size = datasize, 0
    t0 = perf_counter()
    for block in encrypt_file((True, [], [], []), noop_read, a):
      newsize = size + len(block)
      # There is a data copy here, similar to what happens on file.write() calls.
      ciphertext[size:newsize] = block
      size = newsize
    dur = perf_counter() - t0
    enctotal += dur
    print(f"{datasize / dur * 1e-6:6.0f} MB/s", end="", flush=True)

    print("  ➤   DEC", end="", flush=True)
    t0 = perf_counter()
    for data in decrypt_file(([], [], []), ciphertext, a):
      pass
    dur = perf_counter() - t0
    dectotal += dur
    print(f"{datasize / dur * 1e-6:6.0f} MB/s")

  ciphertext.close()
  print(f"Ran {rounds} cycles, each encrypting and then decrypting {datasize * 1e-6:.0f} MB in RAM.\n")
  print(f"Average encryption {rounds * size / enctotal * 1e-6:6.0f} MB/s")
  print(f"Average decryption {rounds * size / dectotal * 1e-6:6.0f} MB/s")
