import os
import sys
from io import BytesIO

from PySide6.QtCore import QRect, QSize, Qt, Slot
from PySide6.QtGui import QGuiApplication, QKeySequence, QPixmap, QShortcut, QStandardItem, QStandardItemModel
from PySide6.QtWidgets import QApplication, QFileDialog, QGridLayout, QHBoxLayout, QInputDialog, QLabel, QLineEdit, QListView, QMenu, QMenuBar, QPlainTextEdit, QPushButton, QSizePolicy, QSpacerItem, QVBoxLayout, QWidget

from covert import passphrase, pubkey, util
from covert.archive import Archive
from covert.blockstream import decrypt_file, encrypt_file
from covert.cli import ARMOR_MAX_SIZE, TTY_MAX_SIZE
from covert.gui.encrypt import AuthInput
from covert.gui.util import datafile, setup_interrupt_handling
from covert.gui.widgets import EncryptToolbar, MethodsWidget


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
    with BytesIO(data) as f:
      del data
      self.decrypt(f)

  @Slot()
  def decrypt_file(self):
    file = QFileDialog.getOpenFileName(self, "Covert - Open file", "", "Covert Binary or Armored (*)")[0]
    if not file:
      return
    if 40 <= os.path.getsize(file) <= ARMOR_MAX_SIZE:
      # Try reading the file as armored text rather than binary
      with open(file, "rb") as f:
        data = f.read()
      try:
        f = BytesIO(util.armor_decode(data.decode()))
      except ValueError:
        f = BytesIO(data)
      del data
      with f:
        self.decrypt(f)
      return
    # Process as binary
    with open(file, "rb") as f:
      with suppress(OSError):
        f = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
      with f:
        self.decrypt(f)

  def decrypt(self, infile):
    self.auth.setVisible(False)
    self.plaintext.clear()
    a = Archive()
    f = None
    def authgen():
      # FIXME: Should wait for GUI input of auth methods instead
      yield from self.app.identities
      yield from self.app.passwords
    for data in a.decode(decrypt_file(authgen(), infile, a)):
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
              self.plaintext.appendPlainText(f" 💬\n{data.decode()}")
            except UnicodeDecodeError:
              pidx = a.flist.index(prev)
              prev['n'] = f"noname.{pidx + 1:03}"
              prev['renamed'] = True
          f.close()
          f = None
        if prev and 'n' in prev:
          n = prev['n']
          s = prev['s']
          r = '<renamed>' if 'renamed' in prev else ''
          self.plaintext.appendPlainText(f'{s:15,d} 📄 {n:60}{r}'.rstrip())
        if a.curfile:
          n = a.curfile.get('n', '')
          if not n and a.curfile.get('s', float('inf')) < TTY_MAX_SIZE:
            f = BytesIO()
      else:
        if f:
          f.write(data)
