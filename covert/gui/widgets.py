from io import BytesIO

from PySide6.QtCore import QSize, Slot
from PySide6.QtGui import QGuiApplication, QPixmap
from PySide6.QtWidgets import QFileDialog, QHBoxLayout, QLabel, QPushButton, QSizePolicy, QSpacerItem, QWidget

from covert import util
from covert.gui import res
from covert.gui.util import datafile


class MethodsWidget(QWidget):

  def __init__(self, view):
    QWidget.__init__(self)
    self.view = view
    self.layout = QHBoxLayout(self)
    self.layout.setContentsMargins(11, 11, 11, 11)
    if not (view.passwords or view.recipients):
      lock = QLabel()
      lock.setPixmap(res.icons.unlockicon)
      self.layout.addWidget(lock)
      self.layout.addWidget(QLabel(' wide-open – anyone can open the file'))
    else:
      lock = QLabel()
      lock.setPixmap(res.icons.lockicon)
      self.layout.addWidget(lock)
      self.layout.addWidget(QLabel(' covert'))
    self.layout.addItem(QSpacerItem(0, 0, QSizePolicy.Expanding, QSizePolicy.Fixed))
    for p in view.passwords:
      key = QLabel()
      key.setPixmap(res.icons.keyicon)
      self.layout.addWidget(key)
    for k in view.recipients:
      key = QLabel()
      key.setPixmap(res.icons.pkicon)
      self.layout.addWidget(key)
      self.layout.addWidget(QLabel(str(k)))
    for k in view.signatures:
      key = QLabel()
      key.setPixmap(res.icons.signicon)
      self.layout.addWidget(key)
      self.layout.addWidget(QLabel(str(k)))
    clearbutton = QPushButton("Clear keys")
    clearbutton.clicked.connect(self.clearkeys)
    self.layout.addWidget(clearbutton)

  def clearkeys(self):
    self.view.recipients = set()
    self.view.passwords = set()
    self.view.signatures = set()
    self.view.update_views()


class DecryptWidget(QWidget):

  def __init__(self, app):
    QWidget.__init__(self)
    self.app = app
    self.layout = QHBoxLayout(self)
    self.layout.setContentsMargins(11, 11, 11, 11)
    s = self.app.blockstream.header.slot if getattr(self.app, 'blockstream') else ""
    if s == "wide-open":
      lock = QLabel()
      lock.setPixmap(res.icons.unlockicon)
      self.layout.addWidget(lock)
      self.layout.addWidget(QLabel(' wide-open – anyone can open the file'))
    else:
      lock = QLabel()
      lock.setPixmap(res.icons.lockicon)
      self.layout.addWidget(lock)
      text = f"{s[1]} recipients - unlocked by slot auth{s[0]}" if isinstance(s, tuple) else s
      self.layout.addWidget(QLabel(f" {text}"))
    self.layout.addItem(QSpacerItem(0, 0, QSizePolicy.Expanding, QSizePolicy.Fixed))
    clearbutton = QPushButton("Clear keys")
    clearbutton.clicked.connect(self.clearkeys)
    self.layout.addWidget(clearbutton)

  def clearkeys(self):
    self.app.recipients = set()
    self.app.passwords = set()
    self.app.signatures = set()
    self.app.update_encryption_views()



class EncryptToolbar(QWidget):

  def __init__(self, app, view):
    QWidget.__init__(self)
    self.app = app
    self.view = view
    self.layout = QHBoxLayout(self)
    self.layout.setContentsMargins(11, 11, 11, 11)

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
    self.view.files |= set(QFileDialog.getOpenFileNames(self, "Covert - Attach files")[0])
    self.view.update_views()

  @Slot()
  def attachdir(self):
    self.view.files.add(QFileDialog.getExistingDirectory(self, "Covert - Attach a folder"))
    self.view.update_views()

  @Slot()
  def copyarmor(self):
    outfile = BytesIO()
    self.view.encrypt(outfile)
    outfile.seek(0)
    data = util.armor_encode(outfile.read())
    QGuiApplication.clipboard().setText(f"```\n{data}\n```\n")
    self.app.flash("Covert message copied to clipboard.")

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
      self.view.encrypt(outfile)
      outfile.seek(0)
      data = util.armor_encode(outfile.read())
      with open(name, 'wb') as f:
        f.write(f"{data}\n".encode())
      return
    with open(name, 'wb') as f:
      self.view.encrypt(f)
    self.app.flash(f"Encrypted message saved as {name}")
