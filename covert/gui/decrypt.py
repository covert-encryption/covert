from pathlib import Path

from nacl.exceptions import CryptoError
from PySide6.QtCore import QSize, Qt, Slot
from PySide6.QtGui import QKeySequence, QShortcut, QStandardItem, QStandardItemModel
from PySide6.QtWidgets import *
from showinfm import show_in_file_manager

from covert import passphrase, pubkey, util
from covert.archive import Archive
from covert.blockstream import BlockStream
from covert.gui import res


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
    self.app = app
    self.blockstream = blockstream
    self.plaintext = QPlainTextEdit()
    self.plaintext.setTabChangesFocus(True)
    self.attachments = QTreeWidget()
    self.attachments.setColumnCount(2)
    self.attachments.setHeaderLabels(["Name", "Size", "Notes"])
    self.attachments.setColumnWidth(0, 400)
    self.attachments.setColumnWidth(1, 80)
    self.toolbar = ArchiveToolbar(app, self)
    self.layout = QVBoxLayout(self)
    self.layout.addWidget(self.plaintext)
    self.layout.addWidget(self.attachments)
    self.layout.addWidget(self.toolbar)
    self.init_extract()

  def init_extract(self):
    a = Archive()
    f = None
    # This loads all attached files to RAM.
    # TODO: Handle large files by streaming & filename sanitation
    attachments = 0
    for data in a.decode(self.blockstream.decrypt_blocks()):
      if isinstance(data, dict):
        # Index
        pass
      elif isinstance(data, bool):
        # Nextfile
        prev = a.prevfile
        if prev:
          # Is it a displayable message
          if prev.name is None:
            try:
              self.plaintext.appendPlainText(f"{prev.data.decode()}\n")
            except UnicodeDecodeError:
              pidx = a.flist.index(prev)
              prev.name = f"noname.{pidx + 1:03}"
              prev.renamed = True
          # Treat as an attached file
          if prev.name:
            item = QTreeWidgetItem(self.attachments)
            #item = QStandardItem(res.icons.fileicon, f"{prev.size:,} {prev.name}")
            item.setIcon(0, res.icons.fileicon)
            item.setText(0, prev.name)
            item.setText(1, f"{prev.size:,}")
            item.setTextAlignment(1, Qt.AlignRight)
            attachments += 1
        if a.curfile:
          a.curfile.data = bytearray()
      else:
        a.curfile.data += data

    self.archive = a

    if not attachments:
      self.attachments.setVisible(False)
      self.toolbar.extract.setEnabled(False)
    if not self.plaintext.toPlainText():
      self.plaintext.setVisible(False)

  def extract(self):
    path = QFileDialog.getExistingDirectory(self, "Covert - Extract To")
    if not path: return
    outdir = Path(path)
    mainlevel = set()
    for fi in self.archive.flist:
      if not fi.name: continue
      name = outdir / fi.name
      if not name.resolve().is_relative_to(outdir) or name.is_reserved():
        raise ValueError(f"Invalid filename {fi.name}")
      # Collect main level names (files or folders)
      mname = name
      while mname.parent != outdir:
        mname = mname.parent
      mainlevel.add(str(mname))
      # Write the file
      name.parent.mkdir(parents=True, exist_ok=True)
      with open(name, "wb") as f:
        f.write(fi.data)
    self.app.flash(f"Files extracted to {outdir}")
    # Support for selecting multiple files is too broken, but we get:
    # - A single attachment file is selected (outdir shown)
    # - A single attachment folder is shown (contents of)
    # - Multiple files/folders are shown in outdir but not selected
    show_in_file_manager(mainlevel.pop() if len(mainlevel) == 1 else str(outdir))


class ArchiveToolbar(QWidget):

  def __init__(self, app, view):
    QWidget.__init__(self)
    self.app = app
    self.view = view
    self.layout = QHBoxLayout(self)
    self.layout.setContentsMargins(11, 11, 11, 11)

    self.extract = QPushButton(res.icons.attachicon, " &Extract All")
    self.extract.setIconSize(QSize(24, 24))
    self.layout.addItem(QSpacerItem(0, 0, QSizePolicy.Expanding))
    self.layout.addWidget(self.extract)

    self.extract.clicked.connect(self.view.extract)
