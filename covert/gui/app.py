import os
import sys
from contextlib import suppress
from io import BytesIO
from itertools import chain

from PySide6.QtCore import QRect, QSize, Qt, Slot
from PySide6.QtGui import QGuiApplication, QKeySequence, QPixmap, QShortcut, QStandardItem, QStandardItemModel
from PySide6.QtWidgets import QApplication, QFileDialog, QGridLayout, QHBoxLayout, QInputDialog, QLabel, QLineEdit, QListView, QMenu, QMenuBar, QPlainTextEdit, QPushButton, QSizePolicy, QSpacerItem, QVBoxLayout, QWidget

from covert import passphrase, pubkey, util
from covert.archive import Archive
from covert.blockstream import BlockStream, encrypt_file
from covert.cli import ARMOR_MAX_SIZE, TTY_MAX_SIZE
from covert.gui.encrypt import AuthInput
from covert.gui.util import datafile, setup_interrupt_handling
from covert.gui.widgets import DecryptWidget, EncryptToolbar, MethodsWidget


class App(QApplication):

  def __init__(self):
    QApplication.__init__(self, sys.argv)
    self.recipients = set()
    self.signatures = set()
    self.identities = set()
    self.passwords = set()
    self.files = set()

    self.logo = QPixmap(datafile('logo.png'))
    self.newicon = QPixmap(datafile('icons8-new-document-48.png')).scaled(48, 48)
    self.pasteicon = QPixmap(datafile('icons8-paste-48.png')).scaled(48, 48)
    self.openicon = QPixmap(datafile('icons8-cipherfile-64.png')).scaled(48, 48)
    self.fileicon = QPixmap(datafile('icons8-file-64.png')).scaled(24, 24)
    self.foldericon = QPixmap(datafile('icons8-folder-48.png')).scaled(24, 24)
    self.unlockicon = QPixmap(datafile('icons8-unlocked-48.png')).scaled(24, 24)
    self.lockicon = QPixmap(datafile('icons8-locked-48.png')).scaled(24, 24)
    self.keyicon = QPixmap(datafile('icons8-key-48.png')).scaled(24, 24)
    self.pkicon = QPixmap(datafile('icons8-link-48.png')).scaled(24, 24)
    self.signicon = QPixmap(datafile('icons8-signing-a-document-48.png')).scaled(24, 24)
    self.setApplicationName('Covert Encryption')
    self.setObjectName('Covert')
    setup_interrupt_handling()
    self.window = MainWindow(self)
    self.window.show()

    self.update_encryption_views()

  def encrypt(self, outfile):
    # Process the message, prune surrounding whitespace
    msg = self.window.plaintext.toPlainText()
    msg = '\n'.join([l.rstrip() for l in msg.split('\n')]).strip('\n')
    msg = util.encode(msg)
    a = Archive()
    files = list(sorted(self.files))
    a.file_index([msg] + files if msg else files)
    if self.signatures:
      a.index['s'] = [s.edpk for s in self.signatures]
    # Output files
    if isinstance(outfile, BytesIO) and a.total_size > ARMOR_MAX_SIZE:
      raise ValueError("The data is too large for ASCII Armoring. Save as Covert Binary instead.")
    wideopen = not (self.passwords or self.recipients)
    # Main processing
    for block in encrypt_file((wideopen, self.passwords, self.recipients, self.signatures), a.encode, a):
      outfile.write(block)

  def update_encryption_views(self):
    if len(self.recipients) + len(self.passwords) > 20:
      self.recipients = set(list(self.recipients)[:20])
      self.passwords = set(list(self.passwords)[:20 - len(self.recipients)])
      self.window.update_encryption_views()
      raise ValueError("Some recipients were discarded, can only have 20 recipients.")
    self.window.update_encryption_views()

class MainWindow(QWidget):

  def __init__(self, app):
    QWidget.__init__(self)
    QShortcut(QKeySequence("Ctrl+Q"), self).activated.connect(app.quit)
    self.app = app
    self.setGeometry(QRect(10, 10, 800, 600))
    self.logo = QLabel()
    self.logo.setAlignment(Qt.AlignTop)
    self.logo.setGeometry(QRect(0, 0, 128, 128))
    self.logo.setPixmap(app.logo)
    self.auth = AuthInput(app)
    self.decrauth = AuthDecr(app)
    self.decrauth.setVisible(False)
    self.methods = MethodsWidget(app)
    self.plaintext = QPlainTextEdit()
    self.plaintext.setTabChangesFocus(True)
    self.attachments = QListView()
    self.attmodel = QStandardItemModel(self)
    self.attachments.setModel(self.attmodel)
    self.attachments.setMaximumHeight(120)
    self.attachments.setWrapping(True)
    self.newbutton = QPushButton(self.app.newicon, "&New Message")
    self.pastebutton = QPushButton(self.app.pasteicon, "&Paste Armored")
    self.openbutton = QPushButton(self.app.openicon, "&Open File")
    self.newbutton.setIconSize(QSize(48, 48))
    self.pastebutton.setIconSize(QSize(48, 48))
    self.openbutton.setIconSize(QSize(48, 48))
    self.newbutton.clicked.connect(self.encrypt_new)
    self.pastebutton.clicked.connect(self.decrypt_paste)
    self.openbutton.clicked.connect(self.decrypt_file)

    self.layout = QGridLayout(self)
    self.layout.setContentsMargins(0, 0, 0, 0)
    self.layout.setSpacing(0)
    self.layout.addWidget(self.logo, 0, 0, 4, 1)
    self.layout.addItem(QSpacerItem(0, 0, QSizePolicy.Expanding, QSizePolicy.Fixed), 0, 1)
    self.layout.addItem(QSpacerItem(0, 0, QSizePolicy.Expanding, QSizePolicy.Fixed), 0, 6)
    self.layout.addWidget(self.newbutton, 0, 2)
    self.layout.addItem(QSpacerItem(11, 0, QSizePolicy.Expanding, QSizePolicy.Fixed), 0, 3)
    self.layout.addWidget(self.pastebutton, 0, 4)
    self.layout.addWidget(self.openbutton, 0, 5)
    self.layout.addItem(QSpacerItem(0, 11), 1, 2, 1, 4)
    self.layout.addWidget(self.auth, 2, 2, 1, 4)
    self.layout.addWidget(self.decrauth, 2, 2, 1, 4)
    self.layout.addItem(QSpacerItem(0, 11), 3, 2, 1, 4)
    self.layout.addWidget(self.methods, 4, 0, 1, -1)
    self.layout.addWidget(self.plaintext, 5, 0, 1, -1)
    self.layout.addWidget(self.attachments, 6, 0, 1, -1)
    self.layout.addWidget(EncryptToolbar(app), 7, 0, 1, -1)

    # Override CLI password asking with GUI version
    passphrase.ask = self.askpass

  def askpass(self, prompt, create=False):
    return QInputDialog.getText(self, "Covert Encryption", f"{prompt}:", QLineEdit.Password, "")

  def update_encryption_views(self):
    self.auth.siginput.setText(', '.join(str(k) for k in self.app.signatures) or "Anonymous (no signature)")

    self.methods.deleteLater()
    self.methods = MethodsWidget(self.app)
    self.layout.addWidget(self.methods, 4, 0, 1, -1)

    self.attachments.setVisible(bool(self.app.files))
    self.attmodel.clear()
    for a in list(sorted(self.app.files)):
      icon = self.app.foldericon if os.path.isdir(a) else self.app.fileicon
      item = QStandardItem(icon, a.split('/')[-1])
      self.attmodel.appendRow(item)


  def update_decryption_views(self):
    self.methods.deleteLater()
    self.methods = DecryptWidget(self.app)
    self.layout.addWidget(self.methods, 4, 0, 1, -1)

  @Slot()
  def encrypt_new(self):
    self.auth.setVisible(True)
    self.plaintext.setPlainText("")
    self.app.attachments = {}
    self.app.update_encryption_views()
    self.plaintext.setFocus()

  @Slot()
  def decrypt_paste(self):
    data = util.armor_decode(QGuiApplication.clipboard().text())
    self.decrypt(data)

  @Slot()
  def decrypt_file(self):
    file = QFileDialog.getOpenFileName(self, "Covert - Open file", "", "Covert Binary or Armored (*)")[0]
    if not file:
      return
    # TODO: Implement in a thread using mmap instead
    with open(file, "rb") as f:
      data = f.read()
    if 40 <= len(data) <= ARMOR_MAX_SIZE:
      # Try reading the file as armored text rather than binary
      with suppress(ValueError):
        data = util.armor_decode(data.decode())
    self.decrypt(data)

  def decrypt(self, infile):
    self.auth.setVisible(False)
    self.plaintext.clear()
    a = Archive()
    f = None
    b = BlockStream()
    b.decrypt_init(infile)
    # Try decrypting with everything the user has entered
    for a in chain(self.app.identities, self.app.signatures, self.app.passwords):
      if b.header.key:
        break
      with suppress(CryptoError):
        b.authenticate(a)
    self.app.blockstream = b
    self.decrypt_attempt()

  def decrypt_attempt(self):
    b = self.app.blockstream
    self.update_decryption_views()
    if not b.header.key:
      self.decrauth.note.setText(f"Unable to decrypt. Enter passphrase or key.")
      self.decrauth.setVisible(True)
      return
    self.decrauth.setVisible(False)
    s = b.header.slot
    a = Archive()
    f = None
    for data in a.decode(b.decrypt_blocks()):
      if isinstance(data, dict):
        # Index
        pass
      elif isinstance(data, bool):
        # Nextfile
        prev = a.prevfile
        if f:
          if isinstance(f, BytesIO):
            f.seek(0)
            data = f.read()
            try:
              self.plaintext.appendPlainText(f"{data.decode()}\n")
            except UnicodeDecodeError:
              pidx = a.flist.index(prev)
              prev.name = f"noname.{pidx + 1:03}"
              prev.renamed = True
          f.close()
          f = None
        #if prev and prev.name is not None:
          #r = '<renamed>' if prev.renamed else ''
          #self.plaintext.appendPlainText(f'{prev.size:15,d} 📄 {prev.name:60}{r}'.rstrip())
        if a.curfile:
          # Is it a displayable message?
          if a.curfile.name is None and a.curfile.size is not None and a.curfile.size < TTY_MAX_SIZE:
            f = BytesIO()
      else:
        if f:
          f.write(data)


class AuthDecr(QWidget):

  def __init__(self, app):

    QWidget.__init__(self)
    self.setMinimumWidth(535)
    self.app = app
    self.init_keyinput()
    self.init_passwordinput()
    self.layout = QGridLayout(self)
    self.layout.setContentsMargins(11, 11, 11, 11)
    self.layout.addWidget(QLabel("Secret key:"), 0, 0)
    self.layout.addWidget(self.siginput, 0, 1)
    self.layout.addWidget(self.skfile, 0, 4)
    self.layout.addWidget(QLabel("Passphrase:"), 1, 0)
    self.layout.addWidget(self.pw, 1, 1, 1, 2)
    self.layout.addWidget(self.addbutton, 1, 4)
    self.layout.addWidget(self.note, 2, 0, 1, 4)



  def init_passwordinput(self):
    self.pw = QLineEdit()
    self.addbutton = QPushButton("Decrypt")
    self.addbutton.clicked.connect(self.addpassword)
    QShortcut(QKeySequence("Return"), self.pw, context=Qt.WidgetShortcut).activated.connect(self.addpassword)
    QShortcut(QKeySequence("Tab"), self.pw, context=Qt.WidgetShortcut).activated.connect(self.tabcomplete)
    QShortcut(QKeySequence("Ctrl+H"), self.pw, context=Qt.WidgetShortcut).activated.connect(self.togglehide)
    self.pw.setEchoMode(QLineEdit.EchoMode.Password)
    self.note = QLabel('Passphrase:')
    self.visible = False

  def init_keyinput(self):
    self.siginput = QLineEdit()
    self.siginput.setDisabled(True)
    self.siginput.setReadOnly(True)
    self.siginput.setFixedWidth(260)
    self.skfile = QPushButton('Open keyfile')
    self.skfile.clicked.connect(self.loadsk)

  @Slot()
  def togglehide(self):
    self.visible = not self.visible
    self.pw.setEchoMode(QLineEdit.EchoMode.Normal if self.visible else QLineEdit.EchoMode.Password)

  @Slot()
  def addpassword(self):
    pw = self.pw.text()
    try:
      pwhash = passphrase.pwhash(util.encode(pw))
    except ValueError:
      return
    self.app.passwords.add(pwhash)
    self.pw.setText("")
    self.app.update_encryption_views()
    try:
      self.app.blockstream.authenticate(pwhash)
    except Exception as e:
      self.note.setText(f"Error: {e}")
      return
    self.app.window.decrypt_attempt()

  @Slot()
  def tabcomplete(self):
    pw, pos, hint = passphrase.autocomplete(self.pw.text(), self.pw.cursorPosition())
    self.pw.setText(pw)
    self.pw.setCursorPosition(pos)
    if hint:
      self.note.setText('Autocomplete: ' + hint)


  @Slot()
  def loadsk(self):
    file = QFileDialog.getOpenFileName(self, "Covert - Open secret key", "",
      "SSH, Minisign and Age private keys (*)")[0]
    if not file:
      return
    keys = set(pubkey.read_sk_file(file))
    self.app.identities |= keys
    self.app.update_encryption_views()
    for i, k in enumerate(keys):
      try:
        self.app.blockstream.authenticate(k)
      except Exception as e:
        if i < len(keys) - 1:
          continue
        self.decrauth.note.setText(f"Error: {e}")
        return
    self.app.window.decrypt_attempt()
