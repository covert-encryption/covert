import sys
from typing import NoReturn

import covert

T = "\x1B[1;44m"  # titlebar (white on blue)
H = "\x1B[1;37m"  # heading (bright white)
C = "\x1B[0;34m"  # command (dark blue)
F = "\x1B[1;34m"  # flag (light blue)
D = "\x1B[1;30m"  # dark / syntax markup
N = "\x1B[0m"     # normal color

usage = dict(
  enc=f"""\
{C}covert {F}enc --id{N} you:them {D}[{N}{F}-r{N} pubkey {D}|{N} {F}-R{N} pkfile{D}]  ⋯{N}
{C}covert {F}enc {D}[{F}-i {N}id.key{D}] [{F}-r {N}pubkey {D}|{N} {F}-R {N}pkfile {D}|{F} -p {D}|{F} --wide-open{D}]…  ⋯
        ⋯  [{F}--pad {N}5{D}] [{F}-A {D}| [{F}-o {N}cipher.dat {D}[{F}-a{D}]] [{N}file.jpg{D}]…{N}
""",
  dec=f"{C}covert {F}dec {D}[{F}--id {N}you:them{D}] [{F}-i {N}id.key{D}] [{F}-A {D}|{N} cipher.dat{D}] [{F}-o {N}files/{D}]{N}\n",
  id=f"{C}covert {F}id {D}[{N}you:them{D}] [{N}options{D}] —{N} create/manage ID store of your keys\n",
  edit=f"{C}covert {F}edit {N}cipher.dat {D}—{N} securely keep notes with passphrase protection\n",
  bench=f"{C}covert {F}bench {D}—{N} run a performance benchmark for decryption and encryption\n",
)

usagetext = dict(
  enc=f"""\
Encrypt a message and/or files. The first form uses ID store, while the second
does not and instead takes all keys on the command line. When no files are
given or {F}-{N} is included, Covert asks for message input or reads stdin.

  {F}--id {N}alice:bob    Use ID store for local (alice) and peer (bob) keys
  {F}-i {N}seckey         Sign the message with your secret key
  {F}-r {N}pubkey {F}-R{N} file Encrypt the message for this public key
  {F}-p{N}                Passphrase encryption (default when no other options)
  {F}--wide-open{N}       Allow anyone to open the file (no keys or passphrase)

  {F}--pad{N} PERCENT     Preferred random padding amount (default 5 %)
  {F}-o{N} FILENAME       Output file (binary ciphertext that looks entirely random)
  {F}-a{N}                ASCII/text output (default for terminal/clipboard)
  {F}-A{N}                Auto copy&paste of ciphertext (desktop use)

With ID store, no keys need to be defined on command line, although as a
shortcut one may store a new peer by specifiying a previously unused peer name
and his public key by {C}covert {F}enc --id {N}you:newpeer{F} -r{N} key {D}⋯{N}  avoiding the use
of the {F}id{N} subcommand to add the peer public key first. Conversations already
established use forward secret keys and should have no key specified on {F}enc{N}.

Folders may be specified as input files and they will be stored recursively.
Any paths given on command line are stripped off the stored names, such that
each item appears at archive root, avoiding accidental leakage of metadata.
""",
  dec=f"""\
Decrypt Covert archive. Tries decryption with options given on command line,
and with all conversations and keys stored in ID store.

  {F}--id {N}alice:bob    Store the sender as "bob" if not previously known
  {F}-i {N}seckey         Sign the message with your secret key
  {F}-r {N}pubkey {F}-R{N} file Encrypt the message for this public key
  {F}-p{N}                Passphrase encryption (default when no other options)
  {F}--wide-open{N}       Allow anyone to open the file (no keys or passphrase)
  {F}-o{N} folder         Folder where to extract any attached files.
  {F}-A{N}                Auto copy&paste of ciphertext (desktop use)
""",
  edit=f"""\
Avoids having to extract the message in plain text for editing, which could
leave copies on disk unprotected. Use {C}covert {F}enc{N} with a passphrase to create
the initial archive. Attached files and other data are preserved even though
editing overwrites the entire encrypted file.
""",
  id=f"""\
The ID store keeps your encryption keys stored securely and enables messaging
with forward secrecy. You only need to enter anyone's public key the first
time you send them a message and afterwards all replies use temporary keys
which change with each message sent and received.

  {F}-s --secret{N}       Show secret keys (by default only shows public keys)
  {F}-p --passphrase{N}   Change Master ID passphrase
  {F}-r {N}pk {F}-R {N}pkfile   Change/set the public key associated with ID local:peer
  {F}-i {N}seckey         Change the secret key of the given local ID
  {F}-D --delete{N}       Delete the ID (local and all its peers, or the given peer)
  {F}--delete-entire-idstore{N}  Securely erase the entire ID storage

The storage is created when you run {C}covert {F}id{N} yourname. Be sure to
write down the master passphrase created or change it to one you can remember.
Multiple local IDs can be created for separating one's different tasks and
their contacts, but all share the same master passphrase.

The ID names are for your own information and are never included in messages.
Avoid using spaces or punctuation on them. Notice that your local ID always
comes first, and any peer is separated by a colon. Deletion of a local ID also
removes all public keys and conversations attached to it.
""",
)

cmdhelp = {k: f"{usage[k]}\n{usagetext.get(k, '')}".rstrip("\n") + "\n" for k in usage}

introduction = f"Covert {covert.__version__} - A file and message encryptor with strong anonymity"
if len(introduction) > 78:  # git version string is too long
  introduction = f"Covert {covert.__version__} - A file and message encryptor"

introduction = f"""\
{T}{introduction:78}{N}
 💣  Things encrypted with this developer preview mayn't be readable evermore
"""

shorthelp = f"""\
{introduction}
{"".join(usage.values())}
Getting started: optionally create an ID ({C}covert {F}id{N} yourname), then use the
{F}enc{N} command to send messages and {F}dec{N} to receive them. You won't need most
of the options but see the help for more info. Commonly used options:

  {F}--id {N}alice:bob    Use ID store for local (alice) and peer (bob) keys
  {F}-i {N}seckey         Your secret key file (e.g .ssh/id_ed25519) or keystring
  {F}-r {N}pubkey {F}-R{N} file Their public key, or {F}-R{N} github:username {D}|{N} bob.pub
  {F}-A{N}                Auto copy&paste of ciphertext (desktop use)
  {F}--help --version{N}  Useful information. Help applies to subcommands too.
"""

keyformatshelp = f"""\
{H}Supported key formats and commands to generate keys:{N}

* Age:         {C}covert {F}id{N} yourname      (Covert natively uses Age's key format)
* Minisign:    {C}minisign {F}-R{N}
* SSH ed25519: {C}ssh-keygen {F}-t ed25519{N}   (other SSH key types are not supported)
* WireGuard:   {C}wg {F}genkey {C}| tee {N}secret.key {C}| wg {F}pubkey{N}
"""

exampleshelp = f"""\
{H}Examples:{N}

* To encrypt a message using an ssh-ed25519 public key, run:
  - {C}covert {F}enc -R {N}github:myfriend {F}-o{N} file
  - {C}covert {F}enc -R {N}~/.ssh/myfriend.pub {F}-o{N} file
  - {C}covert {F}enc -r {N}AAAAC3NzaC1lZDI1NTE5AAAA... {F}-o{N} file

* To decrypt a message using a private ssh-ed25519 key file, run:
  - {C}covert {F}dec -i {N}~/.ssh/id_ed25519 file

* Messaging and key storage with ID store:
  - {C}covert {F}id {N}alice                      Add your ID (generate new or {F}-i{N} key)
  - {C}covert {F}id {N}alice:bob {F}-R{N} github:bob    Add bob as a peer for local ID alice
  - {C}covert {F}enc --id {N}alice:bob            Encrypt a message using idstore
  - {C}covert {F}enc --id {N}alice:charlie {F}-r{N} pk  Adding a peer (on initial message)
  - {C}covert {F}dec{N}                           Uses idstore for decryption
"""

allcommands = '\n\n'.join(cmdhelp.values())

fullhelp = f"""\
{introduction}
{allcommands}

{keyformatshelp}
{exampleshelp}"""

def print_help(modehelp: str = None, error: str = None) -> NoReturn:
  stream = sys.stderr if error else sys.stdout
  if modehelp is None: stream.write(shorthelp)
  elif (h := cmdhelp.get(modehelp)): stream.write(h)
  else: stream.write(fullhelp)
  if error:
    stream.write(f"\n{error}\n")
    sys.exit(1)
  sys.exit(0)

def print_version() -> NoReturn:
  print(f"Covert {covert.__version__}")
  sys.exit(0)
