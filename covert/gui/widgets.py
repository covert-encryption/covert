from PySide6.QtCore import QSize, Qt
from PySide6.QtGui import QStandardItem, QStandardItemModel
from PySide6.QtWidgets import QHBoxLayout, QLabel, QPushButton, QSizePolicy, QSpacerItem, QWidget


class MethodsWidget(QWidget):

  def __init__(self, app):
    QWidget.__init__(self)
    self.app = app
    self.layout = QHBoxLayout(self)
    self.layout.setContentsMargins(10, 10, 10, 10)
    if not (app.passwords or app.recipients):
      lock = QLabel()
      lock.setPixmap(app.unlockicon)
      self.layout.addWidget(lock)
      self.layout.addWidget(QLabel(' wide-open – anyone can open the file'))
    else:
      lock = QLabel()
      lock.setPixmap(app.lockicon)
      self.layout.addWidget(lock)
      self.layout.addWidget(QLabel(' covert'))
    self.layout.addItem(QSpacerItem(0, 0, QSizePolicy.Expanding, QSizePolicy.Fixed))
    for p in app.passwords:
      key = QLabel()
      key.setPixmap(app.keyicon)
      self.layout.addWidget(key)
    for k in app.recipients:
      key = QLabel()
      key.setPixmap(app.pkicon)
      self.layout.addWidget(key)
      self.layout.addWidget(QLabel(str(k)))
    for k in app.signatures:
      key = QLabel()
      key.setPixmap(app.signicon)
      self.layout.addWidget(key)
      self.layout.addWidget(QLabel(str(k)))
    clearbutton = QPushButton("Clear keys")
    clearbutton.clicked.connect(self.clearkeys)
    self.layout.addWidget(clearbutton)

  def clearkeys(self):
    self.app.recipients = set()
    self.app.passwords = set()
    self.app.signatures = set()
    self.app.update_encryption_views()
