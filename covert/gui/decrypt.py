from io import BytesIO

from nacl.exceptions import CryptoError
from PySide6.QtCore import QRect, QSize, Qt, QTimer, Slot
from PySide6.QtGui import QAction, QGuiApplication, QKeySequence, QPixmap, QShortcut, QStandardItem, QStandardItemModel
from PySide6.QtWidgets import *

from covert import passphrase, pubkey, util
from covert.archive import Archive
from covert.blockstream import BlockStream
from covert.gui import res
from covert.gui.widgets import DecryptWidget, EncryptToolbar, MethodsWidget
from covert.util import TTY_MAX_SIZE


class DecryptView(QWidget):
  def __init__(self, app, infile):
    QWidget.__init__(self)
    self.blockstream = BlockStream()
    self.blockstream.decrypt_init(infile)

    self.setMinimumWidth(535)
    self.app = app
    self.init_keyinput()
    self.init_passwordinput()
    self.layout = QGridLayout(self)
    self.layout.setContentsMargins(11, 11, 11, 11)
    self.layout.addWidget(QLabel("<h1>Authentication Required</h1><p>If the input is a Covert Archive, it is locked by a public key or by a passphrase.<p>Enter credentials below to decrypt the data."), 0, 0, 1, 3)
    self.layout.addWidget(QLabel("Secret key:"), 1, 0)
    self.layout.addWidget(self.siginput, 1, 1)
    self.layout.addWidget(self.skfile, 1, 2)
    self.layout.addWidget(QLabel("Passphrase:"), 2, 0)
    self.layout.addWidget(self.pw, 2, 1)
    self.layout.addWidget(self.addbutton, 2, 2)

    self.decrypt_attempt()

  def init_passwordinput(self):
    self.pw = QLineEdit()
    self.addbutton = QPushButton("Decrypt")
    self.addbutton.clicked.connect(self.addpassword)
    QShortcut(QKeySequence("Return"), self.pw, context=Qt.WidgetShortcut).activated.connect(self.addpassword)
    QShortcut(QKeySequence("Tab"), self.pw, context=Qt.WidgetShortcut).activated.connect(self.tabcomplete)
    QShortcut(QKeySequence("Ctrl+H"), self.pw, context=Qt.WidgetShortcut).activated.connect(self.togglehide)
    self.pw.setEchoMode(QLineEdit.EchoMode.Password)
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
    except ValueError as e:
      self.app.flash(str(e))
      return
    self.pw.setText("")
    try:
      self.blockstream.authenticate(pwhash)
    except CryptoError:
      self.app.flash("The passphrase was incorrect.")
      return
    self.decrypt_attempt()

  @Slot()
  def tabcomplete(self):
    pw, pos, hint = passphrase.autocomplete(self.pw.text(), self.pw.cursorPosition())
    self.pw.setText(pw)
    self.pw.setCursorPosition(pos)
    if hint:
      self.app.flash('Autocomplete: ' + hint)


  @Slot()
  def loadsk(self):
    file = QFileDialog.getOpenFileName(self, "Covert - Open secret key", "",
      "SSH, Minisign and Age private keys (*)")[0]
    if not file: return
    try:
      keys = set(pubkey.read_sk_file(file))
    except ValueError as e:
      self.app.flash(str(e))
      return
    for i, k in enumerate(keys):
      try:
        self.blockstream.authenticate(k)
      except CryptoError as e:
        if i < len(keys) - 1: continue
        self.app.flash(str(e) or "No suitable key found.")
        return
    self.decrypt_attempt()

  def decrypt_attempt(self):
    if self.blockstream.header.key:
      self.app.setCentralWidget(ArchiveView(self.app, self.blockstream))


class ArchiveView(QWidget):
  def __init__(self, app, blockstream):
    QWidget.__init__(self)
    self.plaintext = QPlainTextEdit()
    self.plaintext.setTabChangesFocus(True)
    self.attachments = QListView()
    self.attmodel = QStandardItemModel(self)
    self.attachments.setModel(self.attmodel)
    self.attachments.setMaximumHeight(120)
    self.attachments.setWrapping(True)
    self.layout = QVBoxLayout(self)
    self.layout.addWidget(self.plaintext)
    self.layout.addWidget(self.attachments)
    a = Archive()
    f = None
    for data in a.decode(blockstream.decrypt_blocks()):
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
        if prev and prev.name:
          item = QStandardItem(res.icons.fileicon, f"{prev.size:,} {prev.name}")
          self.attmodel.appendRow(item)
        if a.curfile:
          # Is it a displayable message?
          if a.curfile.name is None and a.curfile.size is not None and a.curfile.size < TTY_MAX_SIZE:
            f = BytesIO()
      else:
        if f:
          f.write(data)
    self.archive = a
    self.blockstream = blockstream
