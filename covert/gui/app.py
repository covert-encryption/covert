import os
import sys
from io import BytesIO

from PySide6.QtCore import QRect, QSize, Qt, Slot
from PySide6.QtGui import QGuiApplication, QKeySequence, QPixmap, QShortcut, QStandardItem, QStandardItemModel
from PySide6.QtWidgets import (
  QApplication, QFileDialog, QGridLayout, QHBoxLayout, QLabel, QLineEdit, QListView, QMenu, QMenuBar, QPlainTextEdit,
  QPushButton, QSizePolicy, QSpacerItem, QVBoxLayout, QWidget
)

from covert import pubkey, util
from covert.archive import Archive
from covert.blockstream import decrypt_file, encrypt_file
from covert.cli import ARMOR_MAX_SIZE
from covert.gui.pw import PasswordInput
from covert.gui.util import datafile, setup_interrupt_handling
from covert.gui.widgets import MethodsWidget


class App(QApplication):

  def __init__(self):
    QApplication.__init__(self, sys.argv)
    self.recipients = set()
    self.signatures = set()
    self.passwords = set()
    self.files = set()

    self.logo = QPixmap(datafile('logo.png'))
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
      # FIXME: Raise an error message
    if self.signatures:
      self.window.siginput.setText(', '.join(str(k) for k in self.signatures))
    else:
      self.window.siginput.setText("Anonymous (no signature)")

    self.window.methods.deleteLater()
    self.window.methods = MethodsWidget(self)
    self.window.bottomlayout.insertWidget(0, self.window.methods)

    self.window.attachments.setVisible(bool(self.files))
    self.window.attmodel.clear()
    for a in list(sorted(self.files)):
      icon = self.foldericon if os.path.isdir(a) else self.fileicon
      item = QStandardItem(icon, a.split('/')[-1])
      self.window.attmodel.appendRow(item)


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
    self.pw = PasswordInput(app)
    self.plaintext = QPlainTextEdit()
    self.plaintext.setTabChangesFocus(True)
    self.attachments = QListView()
    self.attmodel = QStandardItemModel(self)
    self.attachments.setModel(self.attmodel)
    self.attachments.setMaximumHeight(120)
    self.attachments.setWrapping(True)
    self.layout = QGridLayout(self)
    self.layout.addWidget(self.logo, 0, 0, 1, 1)
    self.layout.setContentsMargins(0, 0, 0, 0)

    self.siginput = QLineEdit()
    self.siginput.setDisabled(True)
    self.siginput.setReadOnly(True)
    self.siginput.setFixedWidth(260)
    self.pkinput = QLineEdit()
    self.pkinput.setFixedWidth(260)
    self.pkinput.setPlaceholderText("SSH/Minisign/Age pubkey, or github:user")

    self.pkadd = QPushButton('Add')
    self.pkfile = QPushButton('Open keyfile')
    self.skfile = QPushButton('Open keyfile')

    keylayout = QGridLayout()
    keylayout.setContentsMargins(10, 10, 10, 10)
    keylayout.addWidget(QLabel("Sender:"), 0, 0)
    keylayout.addWidget(self.siginput, 0, 1)
    keylayout.addWidget(self.skfile, 0, 4)
    keylayout.addWidget(QLabel('Recipient public keys or a password may be used for encryption.'), 1, 0, 1, 6)
    keylayout.addWidget(QLabel("Recipient:"), 2, 0)
    keylayout.addWidget(self.pkinput, 2, 1)
    keylayout.addWidget(self.pkadd, 2, 2)
    keylayout.addItem(QSpacerItem(10, 1), 2, 3)
    keylayout.addWidget(self.pkfile, 2, 4)
    keylayout.addItem(QSpacerItem(0, 0, QSizePolicy.Expanding, QSizePolicy.Fixed), 0, 5)
    toplayout = QVBoxLayout()
    toplayout.setContentsMargins(0, 0, 0, 0)
    toplayout.addLayout(keylayout)
    toplayout.addWidget(self.pw)
    toplayout.addItem(QSpacerItem(0, 30))

    QShortcut(QKeySequence("Return"), self.pkinput, context=Qt.WidgetShortcut).activated.connect(self.decodepk)
    self.pkadd.clicked.connect(self.decodepk)
    self.pkfile.clicked.connect(self.loadpk)
    self.skfile.clicked.connect(self.loadsk)

    self.methods = MethodsWidget(app)

    self.bottomlayout = bottomlayout = QVBoxLayout()
    bottomlayout.setContentsMargins(0, 0, 0, 0)
    bottomlayout.setSpacing(0)
    bottomlayout.addWidget(self.methods)
    bottomlayout.addWidget(self.plaintext)
    bottomlayout.addWidget(self.attachments)
    bottomlayout.addWidget(EncryptToolbar(app))
    self.layout.addLayout(toplayout, 0, 1)
    self.layout.addLayout(bottomlayout, 1, 0, 1, 2)

  @Slot()
  def decodepk(self):
    # In CLI github is considered a file, and here not (because not from file dialog)
    # Need to handle this logic mismatch here
    keystr = self.pkinput.text()
    if keystr.startswith('github:'):
      self.app.recipients |= set(pubkey.read_pk_file(keystr))
    else:
      self.app.recipients.add(pubkey.decode_pk(keystr))
      self.app.update_encryption_views()
    self.pkinput.setText("")

  @Slot()
  def loadpk(self):
    file = QFileDialog.getOpenFileName(
      self, "Covert - Open public key", "", "SSH, Minisign and Age public keys (*.pub);;All files (*)"
    )[0]
    if not file:
      return
    self.app.recipients |= set(pubkey.read_pk_file(file))
    self.app.update_encryption_views()

  @Slot()
  def loadsk(self):
    file = QFileDialog.getOpenFileName(self, "Covert - Open secret key", "",
      "SSH, Minisign and Age private keys (*)")[0]
    if not file:
      return
    self.app.signatures = set(pubkey.read_sk_file(file))
    self.app.update_encryption_views()


class EncryptToolbar(QWidget):

  def __init__(self, app):
    QWidget.__init__(self)
    self.app = app
    self.layout = QHBoxLayout(self)
    self.layout.setContentsMargins(10, 10, 10, 10)

    attachicon = QPixmap(datafile('icons8-attach-48.png'))
    copyicon = QPixmap(datafile('icons8-copy-48.png'))
    saveicon = QPixmap(datafile('icons8-save-48.png'))
    attach = QPushButton(attachicon, " Attach &Files")
    attachdir = QPushButton(attachicon, " Fol&der")
    copy = QPushButton(copyicon, " &Armored")
    save = QPushButton(saveicon, " &Save")
    attach.setIconSize(QSize(24, 24))
    attachdir.setIconSize(QSize(24, 24))
    copy.setIconSize(QSize(24, 24))
    save.setIconSize(QSize(24, 24))
    self.layout.addWidget(attach)
    self.layout.addWidget(attachdir)
    self.layout.addItem(QSpacerItem(0, 0, QSizePolicy.Expanding))
    self.layout.addWidget(copy)
    self.layout.addWidget(save)

    attach.clicked.connect(self.attach)
    attachdir.clicked.connect(self.attachdir)
    copy.clicked.connect(self.copyarmor)
    save.clicked.connect(self.savecipher)

  @Slot()
  def attach(self):
    self.app.files |= set(QFileDialog.getOpenFileNames(self, "Covert - Attach files")[0])
    self.app.update_encryption_views()

  @Slot()
  def attachdir(self):
    self.app.files.add(QFileDialog.getExistingDirectory(self, "Covert - Attach a folder"))
    self.app.update_encryption_views()

  @Slot()
  def copyarmor(self):
    outfile = BytesIO()
    self.app.encrypt(outfile)
    outfile.seek(0)
    data = util.armor_encode(outfile.read())
    QGuiApplication.clipboard().setText(f"```\n{data.decode()}\n```\n")

  @Slot()
  def savecipher(self):
    name = QFileDialog.getSaveFileName(
      self, 'Covert - Save ciphertext', "", 'ASCII Armored - good stealth (*.txt);;Covert Binary - maximum stealth (*)',
      'Covert Binary - maximum stealth (*)'
    )[0]
    if not name:
      return
    if name.lower().endswith('.txt'):
      outfile = BytesIO()
      self.app.encrypt(outfile)
      outfile.seek(0)
      data = util.armor_encode(outfile.read())
      with open(name, 'wb') as f:
        f.write(data + b"\n")
      return
    with open(name, 'wb') as f:
      self.app.encrypt(f)
