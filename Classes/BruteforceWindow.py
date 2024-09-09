# Usar QRunnable para hacer ataques de fuerza bruta.
# Primer nivel IPs, segundo nivel Ataques - Info - Ataques previos
# Tercer nivel: Ataques -> Selector con stacked view (la mayoria el normal solo seleccionar)
# Ataques --> Selector de protocolo, Indicar si usuario o diccionario, contraseña o usuario y opciones especiales
# Info -> Misma tabla que en Shodan Query
# Ataques previos -> Mostrar cada ataque y al expandir resultado y abrir txt
# Añadir posibilidad de borrar dispositivo

import os
import json
import shutil
import datetime
from PySide6.QtWidgets import *
from PySide6.QtCore import *
from PySide6.QtWebEngineWidgets import QWebEngineView
from . import Controller

""" Esta clase permite al usuario obtener dispositivos de Shodan a partir de una query
    y añadir estos dispositivos al módulo de ataque de fuerza bruta."""
class BruteforceWindow(QWidget):

    layoutW1 = QVBoxLayout()
    treeWidget = QTreeWidget()
    timer = QTimer()
    threadPool = QThreadPool()

    # Se define el constructor de la clase. En este, se crean y gestionan los diversos elementos de la interfaz.
    def __init__(self, parent):
        super().__init__()
        self.layoutW1.addWidget(self.treeWidget)
        self.setLayout(self.layoutW1)
        self.setWindowTitle("Shodan queries")

    # Permite añadir los dispositivos encontrados mediante una búsqueda en Shodan.
    def initializeTreeWidget(self):
        self.treeWidget.clear()
        self.treeWidget.setColumnCount(1)
        self.treeWidget.setHeaderLabels(["Devices"])
        self.treeWidget.header().setDefaultAlignment(Qt.AlignmentFlag.AlignHCenter)
        devicesFolder = os.getcwd() + os.sep + "Bruteforce"
        devices = os.listdir(devicesFolder)
        for device in devices:
            if ".gitignore" in devices:
                devices.remove(device)
        items = []
        for device in devices:
            firstLevel = QTreeWidgetItem([device])
            currentDeviceFolder = devicesFolder + os.sep + device
            """En esta parte del código se crea el apartado de la información del dispositivo."""
            infoFolder = currentDeviceFolder + os.sep + "Info"
            infoItem = QTreeWidgetItem(["Device information"])
            tableChildItem = QTreeWidgetItem(["Table placeholder"])
            infoItem.addChild(tableChildItem)
            infoFile = os.listdir(infoFolder)[0]
            with open(infoFolder + os.sep +  infoFile, 'r') as advanceInfoFile:
                advanceInfoDict = json.loads(advanceInfoFile.read())
            if "Shodan" in infoFile:
                advanceInfoTable = Controller.createDeviceInfoTable(advanceInfoDict, True)
                buttonsChildItem = QTreeWidgetItem(["Buttons placeholder"])
                infoItem.addChild(buttonsChildItem)
                self.treeWidget.setItemWidget(tableChildItem, 0, advanceInfoTable)
                advancedButton = QPushButton("Advanced info")
                advancedButton.pressed.connect(lambda b=device: Controller.createAdvancedInfoPopup(self, b))
                self.treeWidget.setItemWidget(buttonsChildItem, 0, advancedButton)
            else:
                advanceInfoTable = Controller.createDeviceInfoTable(advanceInfoDict, False)
                self.treeWidget.setItemWidget(tableChildItem, 0, advanceInfoTable)
            """En esta parte del código se crea el apartado de ataques de fuerza bruta."""
            attacksItem = QTreeWidgetItem(["Bruteforce attacks"])
            # Se obtienen los puertos disponibles en el dispositivo
            openPorts = []
            if 'ports' in advanceInfoDict:
                openPorts = map(str, advanceInfoDict['ports'])
            if 'scan' in advanceInfoDict:
                scanDict = list(advanceInfoDict['scan'].values())[0]
                for port in scanDict['tcp'].keys():
                    if scanDict['tcp'][port]['state'] == 'open':
                        openPorts.append(port)
            # Se crea la parte que permite añadir funcionalidades extras presentes en los protocolos AMQP, MQTT, SSH y HTTP.
            differentOptionsLayout = QStackedLayout()
            optionsWidget = QWidget()
            # Opciones para aquellos protocolos sin opciones.
            noExtraOptionLayout = QHBoxLayout()
            noExtraOptionLayout.invalidate()
            noExtraOption = QLabel("")
            noExtraOptionLayout.addWidget(noExtraOption)
            noExtraOptionWidget = QWidget(optionsWidget)
            noExtraOptionWidget.setLayout(noExtraOptionLayout)
            differentOptionsLayout.addWidget(noExtraOptionWidget)
            # Opciones para AMQP.
            amqpSslCheck = QCheckBox("Activate Ssl")
            differentOptionsLayout.addWidget(amqpSslCheck)
            # Opciones para MQTT
            mqttLayout = QHBoxLayout()
            mqttLayout.addWidget(QLabel("Client identifier (default=legba):"))
            mqttV5Check = QCheckBox("Use MQTT v5")
            mqttLayout.addWidget(mqttV5Check)
            mqttClientId = QTextEdit()
            mqttLayout.addWidget(mqttClientId)
            mqttWidget = QWidget(optionsWidget)
            mqttWidget.setLayout(mqttLayout)
            differentOptionsLayout.addWidget(mqttWidget)
            # Opciones para SSH
            sshLayout = QHBoxLayout()
            sshAuthMode = QComboBox()
            sshAuthMode.addItems(["password", "key"])
            sshKeyPassPhrase = QTextEdit()
            sshLayout.addWidget(QLabel("Select password or key authentication (and optional private key passphrase if needed):"))
            sshLayout.addWidget(sshAuthMode)
            sshLayout.addWidget(sshKeyPassPhrase)
            sshWidget = QWidget(optionsWidget)
            sshWidget.setLayout(sshLayout)
            differentOptionsLayout.addWidget(sshWidget)
            # Opciones para HTTP
            httpLayout = QVBoxLayout()
            httpOptions = QComboBox()
            httpOptionsLayout = QHBoxLayout()
            httpOptionsLayout.addWidget(QLabel("Authentication:"))
            httpOptions.addItems(["requests", "basic", "ntlm1", "ntlm2"])
            httpOptionsLayout.addWidget(httpOptions)
            httpLayout.addLayout(httpOptionsLayout)
            httpTargetLayout = QHBoxLayout()
            httpTargetLayout.addWidget(QLabel("URL to bruteforce:"))
            httpTarget = QLineEdit()
            httpTarget.setToolTip("Add the url to bruteforce, like http//ip:port/restofurl")
            httpTargetLayout.addWidget(httpTarget)
            httpLayout.addLayout(httpTargetLayout)
            httpMethodsLayout = QHBoxLayout()
            httpMethods = QComboBox()
            httpMethods.addItems(["GET", "POST"])
            httpMethodsLayout.addWidget(QLabel("HTTP Method:"))
            httpMethodsLayout.addWidget(httpMethods)
            httpLayout.addLayout(httpMethodsLayout)
            httpNtlmOptionsLayout = QHBoxLayout()
            httpNtlmDomainCheck = QCheckBox("Ntml Domain")
            httpNtlmDomain = QLineEdit()
            httpNtlmWorkstationCheck = QCheckBox("Ntml Workstation")
            httpNtlmWorkstation = QLineEdit()
            httpNtlmOptionsLayout.addWidget(httpNtlmDomainCheck)
            httpNtlmOptionsLayout.addWidget(httpNtlmDomain)
            httpNtlmOptionsLayout.addWidget(httpNtlmWorkstationCheck)
            httpNtlmOptionsLayout.addWidget(httpNtlmWorkstation)
            httpLayout.addLayout(httpNtlmOptionsLayout)
            httpPayloadOptionLayout = QHBoxLayout()
            httpPayloadCheck = QCheckBox("Payload to request (query string, post body or form data):")
            httpPayload = QLineEdit()
            httpPayloadOptionLayout.addWidget(httpPayloadCheck)
            httpPayloadOptionLayout.addWidget(httpPayload)
            httpLayout.addLayout(httpPayloadOptionLayout)
            httpSuccessOptionLayout = QHBoxLayout()
            httpSuccessCheck = QCheckBox("String to check if request was correct:")
            httpSuccess = QLineEdit()
            httpSuccessOptionLayout.addWidget(httpSuccessCheck)
            httpSuccessOptionLayout.addWidget(httpSuccess)
            httpLayout.addLayout(httpSuccessOptionLayout)
            httpWidget = QWidget(optionsWidget)
            httpWidget.setLayout(httpLayout)
            differentOptionsLayout.addWidget(httpWidget)
            optionsWidget.setLayout(differentOptionsLayout)
            optionsWidget.setFixedHeight(20)
            bruteforceExtraOptions = QTreeWidgetItem(["Extra options placeholder"])
            # Se añaden los protocolos disponibles en la herramienta.
            comboboxProtocolsChildItem = QTreeWidgetItem(["Combobox for protocols placeholder"])
            protocolsWidget = QWidget()
            protocolsLayout = QHBoxLayout()
            protocolsLayout.addWidget(QLabel("Select service to bruteforce:"))
            protocolsAvailableCombobox = QComboBox()
            protocolsAvailableCombobox.addItems(Controller.protocolsAvailableToBruteforce)
            # Indicamos al selector de protocolos que muestre las opciones necesarias.
            protocolsAvailableCombobox.currentTextChanged.connect(lambda protocol=protocolsAvailableCombobox.currentText(), layout=differentOptionsLayout, widget= optionsWidget, parentItem=attacksItem: self.showProtocolExtraOptions(protocol, layout, widget, parentItem))
            protocolsLayout.addWidget(protocolsAvailableCombobox)
            protocolsWidget.setLayout(protocolsLayout)
            attacksItem.addChild(comboboxProtocolsChildItem)
            self.treeWidget.setItemWidget(comboboxProtocolsChildItem, 0, protocolsWidget)
            # Se añaden los puertos disponibles en el dispositivo.
            comboboxPortsChildItem = QTreeWidgetItem(["Combobox for ports placeholder"])
            portsWidget = QWidget()
            portsLayout = QHBoxLayout()
            portsLayout.addWidget(QLabel("Select port to bruteforce:"))
            portsOpenCombobox = QComboBox()
            portsOpenCombobox.addItems(openPorts)
            portsLayout.addWidget(portsOpenCombobox)
            portsWidget.setLayout(portsLayout)
            attacksItem.addChild(comboboxPortsChildItem)
            self.treeWidget.setItemWidget(comboboxPortsChildItem, 0, portsWidget)
            # Se añade la parte que permite al usuario indicar una lista de usuarios o un usuario en concreto.
            usersChild = QTreeWidgetItem(["Usernames selection placeholder"])
            userDictPathChild = QTreeWidgetItem([""])
            usersWidget = QWidget()
            layoutForUsernames = QHBoxLayout()
            usernamesPathWidget = QFileDialog(caption="Select usernames wordlist")
            usernameDialogButton = QPushButton("Add")
            usernameCheckbox = QCheckBox("Specific user")
            usernameStackedLayout = QStackedLayout()
            specificUsernameWidget = QLineEdit("", usersWidget)
            usernameStackedLayout.addWidget(QLabel("", usersWidget))
            usernameStackedLayout.addWidget(specificUsernameWidget)
            usernameCheckbox.checkStateChanged.connect(lambda checkboxValue=usernameCheckbox, stackedLayout=usernameStackedLayout: self.showSpecificElement(checkboxValue, stackedLayout))
            usernameDialogButton.pressed.connect(lambda fileDialog=usernamesPathWidget, child=userDictPathChild, checkbox=usernameCheckbox, editText=specificUsernameWidget: self.saveUserValue(fileDialog, child, checkbox, editText))
            layoutForUsernames.addWidget(QLabel("Add username/s:"))
            layoutForUsernames.addLayout(usernameStackedLayout)
            layoutForUsernames.addWidget(usernameCheckbox)
            layoutForUsernames.addWidget(usernameDialogButton)
            usersWidget.setLayout(layoutForUsernames)
            attacksItem.addChild(usersChild)
            self.treeWidget.setItemWidget(usersChild, 0, usersWidget)
            attacksItem.addChild(userDictPathChild)
            # Se añade la parte que permite al usuario indicar una lista de contraseñas o una contraseña en concreto.
            passwordsChild = QTreeWidgetItem(["Passwords selection placeholder"])
            passDictPathChild = QTreeWidgetItem([""])
            passWidget = QWidget()
            layoutForPasswords = QHBoxLayout()
            passwordsPathWidget = QFileDialog(caption="Select password wordlist")
            passwordsDialogButton = QPushButton("Add")
            passwordCheckbox = QCheckBox("Specific password")
            passwordStackedLayout = QStackedLayout()
            specificPasswordWidget = QLineEdit("", passWidget)
            passwordStackedLayout.addWidget(QLabel("", passWidget))
            passwordStackedLayout.addWidget(specificPasswordWidget)
            passwordCheckbox.checkStateChanged.connect(lambda checkboxValue=passwordCheckbox, stackedLayout=passwordStackedLayout: self.showSpecificElement(checkboxValue, stackedLayout))
            passwordsDialogButton.pressed.connect(lambda fileDialog=passwordsPathWidget, child=passDictPathChild, checkbox=passwordCheckbox, editText=specificPasswordWidget: self.saveUserValue(fileDialog, child, checkbox, editText))
            layoutForPasswords.addWidget(QLabel("Add password/s:"))
            layoutForPasswords.addLayout(passwordStackedLayout)
            layoutForPasswords.addWidget(passwordCheckbox)
            layoutForPasswords.addWidget(passwordsDialogButton)
            passWidget.setLayout(layoutForPasswords)
            attacksItem.addChild(passwordsChild)
            self.treeWidget.setItemWidget(passwordsChild, 0, passWidget)
            attacksItem.addChild(passDictPathChild)
            # Se añaden los elementos adicionales de los protocolos
            attacksItem.addChild(bruteforceExtraOptions)
            self.treeWidget.setItemWidget(bruteforceExtraOptions, 0, optionsWidget)
            # Se añade el botón para iniciar el ataque de fuerza bruta.
            attackButtonPlaceholder = QTreeWidgetItem(["Attack Button placeholder"])
            runBruteforceButton = QPushButton("Run bruteforce attack")
            runBruteforceButton.pressed.connect(lambda device=device, port=portsOpenCombobox, protocol=protocolsAvailableCombobox, userChild=userDictPathChild, passChild=passDictPathChild,
                                                amqpSsl=amqpSslCheck, mqttV5Check=mqttV5Check, mqttClientId=mqttClientId, sshAuth=sshAuthMode, sshKeyPassPhrase=sshKeyPassPhrase,
                                                httpMode=httpOptions, httpTarget=httpTarget, httpMethod=httpMethods, httpNtlmDomainCheck=httpNtlmDomainCheck, httpNtlmDomain=httpNtlmDomain,
                                                httpNtlmWorkstationCheck=httpNtlmWorkstationCheck, httpNtlmWorkstation=httpNtlmWorkstation, httpPayloadCheck=httpPayloadCheck, httpPayload=httpPayload,
                                                httpSuccessCheck=httpSuccessCheck, httpSuccess=httpSuccess: 
                                                self.runBruteforce(device, port, protocol, userChild, passChild, amqpSsl, mqttV5Check, mqttClientId, sshAuth, sshKeyPassPhrase,
                                                                   httpMode, httpTarget, httpMethod, httpNtlmDomainCheck, httpNtlmDomain, httpNtlmWorkstationCheck, httpNtlmWorkstation,
                                                                   httpPayloadCheck, httpPayload, httpSuccessCheck, httpSuccess))
            attacksItem.addChild(attackButtonPlaceholder)
            self.treeWidget.setItemWidget(attackButtonPlaceholder, 0, runBruteforceButton)
            """ En esta parte del código se crea el apartado de revisar ataques de fuerza previos"""
            previousAttacksItem = QTreeWidgetItem(["Previous attacks"])
            logsPath = currentDeviceFolder + os.sep  + "Attacks" + os.sep
            logsFromDevice = os.listdir(logsPath)
            for log in logsFromDevice:
                currentLogWidget = QWidget()
                currentLogLayout = QHBoxLayout()
                currentLogLabel = QLabel(log, currentLogWidget)
                currentLogButton = QPushButton("See log", currentLogWidget)
                currentLogButton.pressed.connect(lambda pathToLog = logsPath + log: Controller.createLogPopup(self, pathToLog))
                currentLogLayout.addWidget(currentLogLabel)
                currentLogLayout.addWidget(currentLogButton)
                currentLogWidget.setLayout(currentLogLayout)
                currentLogChild = QTreeWidgetItem(["Current log placeholder"])
                previousAttacksItem.addChild(currentLogChild)
                self.treeWidget.setItemWidget(currentLogChild, 0, currentLogWidget)
            """ En esta parte del código se crea el botón para eliminar un dispositivo."""
            deleteChildItem = QTreeWidgetItem(["Delete placeholder"])
            deleteDeviceButton = QPushButton("Delete device")
            deleteDeviceButton.pressed.connect(lambda ip=device: self.deleteDevice(ip))
            # En esta parte se unen las partes que conforman un dispositivo en la interfaz.
            firstLevel.addChild(infoItem)
            firstLevel.addChild(attacksItem)
            firstLevel.addChild(previousAttacksItem)
            firstLevel.addChild(deleteChildItem)
            self.treeWidget.setItemWidget(deleteChildItem, 0, deleteDeviceButton)
            items.append(firstLevel)
        self.treeWidget.insertTopLevelItems(0, items)
    
    # Permite borrar un dispositivo guardado en la herramienta.
    def deleteDevice(self, deviceIp):
        pathToDeviceFolder = os.getcwd() + os.sep + "Bruteforce" + os.sep + deviceIp
        shutil.rmtree(pathToDeviceFolder)
        self.initializeTreeWidget()
        
    # Permite guardar el valor indicado por el usuario para usuarios y contraseñas previo al ataque de fuerza bruta.
    def saveUserValue(self, fileDialog, child, checkbox, editText):
        if not checkbox.isChecked():
            path = fileDialog.getOpenFileName()
            self.treeWidget.setItemWidget(child,0,QLabel("Wordlist selected: " + path[0]))
        else:
            specificValue = editText.text().strip()
            self.treeWidget.setItemWidget(child,0,QLabel("Value selected: " + specificValue))
    
    # Permite mostrar el elemento de la interfaz necesario para indicar que se use un usuario o contraseña en específico.
    def showSpecificElement(self, checkboxValue, stackedLayout):
        if checkboxValue.value == 2:
            stackedLayout.setCurrentIndex(1)
        else:
            stackedLayout.setCurrentIndex(0)
    
    # Permite mostrar al usuario las opciones adicionales del protocolo si es necesario.
    def showProtocolExtraOptions(self, protocol, layout, widget, parent):
        # currentWidget = self.treeWidget.itemWidget(child, 0)
        """
        h = self.stackedWidget.currentWidget().sizeHint().height()
        self.stackedWidget.setFixedHeight(h)
        """
        # currentWidgetLayout = currentWidget.layout()
        neededHeight = 20
        if protocol == "amqp":
            layout.setCurrentIndex(1)
        elif protocol == "mqtt":
            layout.setCurrentIndex(2)
            neededHeight = 40
        elif protocol == "ssh":
            layout.setCurrentIndex(3)
            neededHeight = 40
        elif protocol == "http":
            layout.setCurrentIndex(4)
            neededHeight = 180
        else:
            layout.setCurrentIndex(0)
        widget.setFixedHeight(neededHeight)
        parent.setExpanded(False)
        parent.setExpanded(True)
    
    # Esta función permite realizar un ataque de fuerza bruta de forma paralela a la aplicación.
    def runBruteforce(self, device, portsOpen, protocolSelected, userChild, passChild, 
                      amqpSsl, 
                      mqttV5Check, mqttClientId, 
                      sshAuth, sshKeyPassphrase, 
                      httpMode, httpTarget, httpMethod, httpNtlmDomainCheck, httpNtlmDomain, httpNtlmWorkstationCheck, httpNtlmWorkstation,
                      httpPayloadCheck, httpPayload, httpSuccessCheck, httpSuccess):
        legbaQuery = "\"" + os.getcwd() + os.sep + "Legba" + os.sep
        if os.name == "nt":
            legbaQuery += "Windows" + os.sep + "legba.exe\" "
        else:
            legbaQuery += "Linux" + os.sep + "legba\" "
        # Obtenemos la información del usuario y comprobamos que este añadida correctamente
        try:
            username = self.treeWidget.itemWidget(userChild, 0).text()
            if username == "":
                Controller.createPopup(self, "Username/s not added correctly", "Usernames have not been added successfully, please check it and retry.")
                return
            elif username.split("selected: ")[1] == "":
                Controller.createPopup(self, "Username/s not added correctly", "Usernames have not been added successfully, please check it and retry.")
                return
            else:
                username = username.split("selected: ")[1]
        except:
            Controller.createPopup(self, "Username/s not added correctly", "Usernames have not been added successfully, please check it and retry.")
            return
        try:
            password = self.treeWidget.itemWidget(passChild, 0).text()
            if password == "":
                Controller.createPopup(self, "Password/s not added correctly", "Passwords have not been added successfully, please check it and retry.")
                return
            elif password.split("selected: ")[1] == "":
                Controller.createPopup(self, "Password/s not added correctly", "Passwords have not been added successfully, please check it and retry.")
                return
            else:
                password = password.split("selected: ")[1]
        except:
            Controller.createPopup(self, "Password/s not added correctly", "Passwords have not been added successfully, please check it and retry.")
            return
        outputPath = os.getcwd() + os.sep + "Bruteforce" + os.sep + device + os.sep + "Attacks" + os.sep
        outputPath += protocolSelected.currentText() + "-Port" + portsOpen.currentText() + "-Date" + datetime.datetime.now().strftime('%Y-%m-%d-%H-%M-%S') + ".txt"
        # Creamos el comando de legba acorde a la información proporcionada por el usuario.
        extraArguments = ""
        if protocolSelected.currentText() == "amqp":
            if amqpSsl.isChecked():
                extraArguments = " --amqp-ssl"
        elif protocolSelected.currentText() == "mqtt":
            if not mqttClientId.toPlainText() == "":
                extraArguments += " --mqtt-client-id \"" + mqttClientId.toPlainText() + "\""
            if mqttV5Check.isChecked():
                extraArguments += " --mqtt-v5"
        elif protocolSelected.currentText() == "ssh":
            extraArguments += " --ssh-auth-mode \"" + sshAuth.currentText() + "\""
            if sshAuth.currentText() == "key" and not sshKeyPassphrase.toPlainText() == "":
                extraArguments += " --ssh-key-passphrase \"" + sshKeyPassphrase.toPlainText() + "\""
        elif protocolSelected.currentText() == "http":
            if httpMode.currentText() == "basic":
                legbaQuery += "http.basic"
            elif httpMode.currentText() == "ntlm1" or httpMode.currentText() == "ntlm2":
                legbaQuery += "http." + httpMode.currentText()
                if httpNtlmDomainCheck.isChecked():
                    legbaQuery += " --http-ntlm-domain \"" + httpNtlmDomain.text() + "\""
                if httpNtlmWorkstationCheck.isChecked():
                    legbaQuery += " --http-ntlm-workstation \"" + httpNtlmWorkstation.text() + "\""
            else:
                legbaQuery += "http"
            legbaQuery += " --username \"" + username + "\" --password \"" + password + "\" --target \"" + httpTarget.text() + "\""
            if httpPayloadCheck.isChecked():
                legbaQuery += " --http-payload \'" + httpPayload.text() + "\'"
            if httpSuccessCheck.isChecked():
                legbaQuery += " --http-success-string \"" + httpSuccess.text() + "\""
            legbaQuery += " --http-method \"" + httpMethod.currentText() + "\""
            legbaQuery += " --output \"" + outputPath + "\""
        # Si no es HTTP añadir el resto de la query.
        if not protocolSelected.currentText() == "http": 
            legbaQuery += protocolSelected.currentText() + " --username \"" + username + "\" --password \"" + password
            legbaQuery += "\" --target " + device + ":" + portsOpen.currentText() + extraArguments +  " --output \"" + outputPath + "\""
        with open(outputPath, "w+") as file:
            file.write("The following command for legba has been executed:\n" + legbaQuery + "\nIf there is not results below, it means that no results from the brute force were obtained.\n")
        if os.name == "nt":
            print(legbaQuery)
            os.system("start cmd /k \"" + legbaQuery + "\"")
        else:
            os.system("gnome-terminal -e 'bash -c \"" + legbaQuery + ";bash\"'")