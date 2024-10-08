from PySide6.QtWidgets import *
from PySide6.QtCore import *
from . import Controller
import ping3
import ipaddress
import os


# Clase para la ventana que permite guardar la key de Shodan.
class AddIpManuallyWindow(QWidget):

    userInputElement = QLineEdit("") 
    saveKeyElement = QPushButton("Save IP")
    infoLabel = QLabel("""If the IP is on Shodan and the key is valid,<br> 
                          all the data will come from Shodan. However,<br>
                          if there is no data about the IP, a nmap run<br> 
                          will be done in order to obtain data. However,<br>
                          that nmap run will only cover the default ports<br> 
                          of the protocols available on the brute force module.<br>
                          If you want to check your own device, write localhost.""")
    layoutW1 = QVBoxLayout()
    timer = QTimer()

    # Permite inicializar los elementos necesarios para la ventana.
    def __init__(self, parent):
        super().__init__()
        self.userInputElement.setPlaceholderText("Add IP")
        self.userInputElement.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        self.infoLabel.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        self.saveKeyElement.pressed.connect(self.saveIP)
        self.layoutW1.addWidget(self.userInputElement)
        self.layoutW1.addWidget(self.saveKeyElement)
        self.layoutW1.addWidget(self.infoLabel)
        self.setLayout(self.layoutW1)
        self.setWindowTitle("Add IP Manually")
    
    # Permite guardar una IP, comprobando si se puede encontrar el host.
    def saveIPAux(self):
        QApplication.instance().setOverrideCursor(Qt.CursorShape.BusyCursor)
        userInput = self.userInputElement.text().strip()
        layout = QVBoxLayout()
        infoPopup = QDialog(self)
        ipValid = True
        # Si el sistema es Windows, se realizará un ping para comprobar que se puede llegar a la IP indicada.
        if os.name == "nt":
            if ping3.ping(userInput) == False:
                ipValid = False
                # Comprobación IPv6, ya que ping3 no trabaja con IPv6.
                if ":" in userInput:
                    try:
                        ipaddress.ip_address(userInput)
                        ipValid = True
                    except:
                        ipValid = False
        # Si el sistema no es Windows, no se realizarán pings ICMP (al necesitar root en Linux).
        else:
            try:
                ipaddress.ip_address(userInput)
                ipValid = True
            except:
                ipValid = False
        if ipValid or userInput == "localhost":
            saveIpInfo = Controller.saveIpToBruteforce(userInput)
            infoPopup.setWindowTitle(saveIpInfo[0])
            layout.addWidget(QLabel(saveIpInfo[1]))
        else:
            infoPopup.setWindowTitle("IP not valid")
            layout.addWidget(QLabel("IP is not valid, please check it and try again"))
        QApplication.instance().restoreOverrideCursor()
        closeButton = QDialogButtonBox(QDialogButtonBox.Ok)
        closeButton.accepted.connect(infoPopup.accept)
        layout.addWidget(closeButton)
        infoPopup.setLayout(layout)
        infoPopup.exec()
    
    # La función permite ejecutar el guardado de una IP.
    def saveIP(self):
        self.timer.singleShot(250, self.saveIPAux)