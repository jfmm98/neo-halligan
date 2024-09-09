import shodan
import json
import json2html
import os.path
import nmap
from PySide6.QtWidgets import *
from PySide6.QtCore import *
from . import SearchBarWidget
portsAvailableToBruteforce = [21,22,80,443,1883,3306,5672,27012]
protocolsAvailableToBruteforce = ["ftp", "amqp", "http", "mongodb", "mqtt", "mysql", "ssh"]

# Se obtiene la key actual de Shodan.
def getCurrentShodanKey():
    ShodanKeyFile = open("Shodan Key" + os.sep + "Key.txt", "r")
    ShodanKey = ShodanKeyFile.readline().strip()
    ShodanKeyFile.close()
    return ShodanKey

# Se modifica la key actual de Shodan.
def setCurrentShodanKey(newShodanKey):
    shodanKeyToCheck = newShodanKey.strip()
    shodanApi = shodan.Shodan(shodanKeyToCheck)
    shodanAccountInfo = ""
    try:
        shodanAccountInfo = shodanApi.info()
    except:
        return "Key is not valid, please check it and try again."
    resultToReturn = "Key successfully added!\nCurrent plan: " + shodanAccountInfo['plan'] + ".\nQuery credits left: " + str(shodanAccountInfo['query_credits']) + "."
    ShodanKeyFile = open("./Shodan Key/Key.txt", "w")
    ShodanKeyFile.write(shodanKeyToCheck)
    ShodanKeyFile.close()
    return resultToReturn

# Permite obtener datos de Shodan a partir de la query del usuario.
def realizeShodanQuery(userQuery, numberOfResults):
    shodanKey = getCurrentShodanKey()
    shodanApi = shodan.Shodan(shodanKey)
    queryResult = shodanApi.search(query=userQuery, limit=numberOfResults, minify=False, fields=['ip_str'])
    return queryResult
    # for i in range (len(queryResult)):

# Permite obtener información avanzada sobre un dispositivo en concreto.
def getAdvanceData(deviceIp):
    shodanApi = shodan.Shodan(getCurrentShodanKey())
    advanceResults = shodanApi.host(deviceIp)
    return advanceResults

# Permite obtener información avanzada sobre un dispositivo en concreto en formato JSON.
def getHtmlAdvanceData(deviceIp):
    advanceResults = getAdvanceData(deviceIp)
    dataPartOfResults = advanceResults.pop('data')
    htmlData = "<h3>Device data</h3><br>" + json2html.json2html.convert(json.dumps(advanceResults), clubbing=False)
    htmlData += "<br><h3>Data of each port</h3>"
    for service in dataPartOfResults:
        if "screenshot" in service:
            service["screenshot"]["data"] = """<img src="data:image/jpeg;base64,""" + service["screenshot"]["data"] + """">"""
        jsonOfService = json.dumps(service)
        htmlOfService = json2html.json2html.convert(jsonOfService, clubbing=False)
        htmlOfService = htmlOfService.replace("&lt;", "<").replace("&quot;", "\"").replace("&gt;",">")
        product = ""
        if 'product' in service:
            if service['product'] is not None:
                product = service['product']
        htmlData += "<br><h4>" + str(service['port']) + "/" + service['transport'] + "/" + product + "</h4><br>" + htmlOfService
    htmlData = htmlData.replace("<body", "<body style=\"background-color: transparent\"")
    return htmlData

# Permite guardar una IP en el módulo de fuerza bruta. Si no hay información en Shodan, se ejecutará Nmap.
def saveIpToBruteforce(deviceIp):
    pathToCheck = "Bruteforce" + os.sep + deviceIp
    if os.path.isdir(pathToCheck):
        return ("Already added", "The IP has been already added.")
    else:
        infoDirPath = pathToCheck + os.sep + "Info"
        previousAttacksPath = pathToCheck + os.sep + "Attacks"
        advanceInformation = []
        try:
            advanceInformation = getAdvanceData(deviceIp)
            pathToSave = infoDirPath + os.sep + "Shodan Info.txt"
            messageToUser = "IP has been successfully added and data has been retrieved from Shodan (without spending credits)."
            portsOpen = advanceInformation['ports']
            # Si se añade un dispositivo que no tiene puertos soportados por la herramienta de fuerza bruta.
            if set(portsOpen).isdisjoint(set(portsAvailableToBruteforce)):
                messageToUser += "<br>This device dont have services supported by the bruteforce attacks, but you can still check the data obtained."
        except:
            # Al no haber información en Shodan o ser la key inválida, se ejecuta un script de nmap.
            nmapScanner = nmap.PortScanner()
            advanceInformation = nmapScanner.scan(deviceIp, "21,80,443,993,27017,1883,1433,3306,5432,110,995,3389,6379,9042,22,25,1080,61613,23,5901,445,139", "-T4 -O -sV")
            pathToSave = infoDirPath + os.sep + "Nmap Info.txt"
            messageToUser = "IP has been successfully added and data has been retrieved from Nmap run."
        os.mkdir(pathToCheck)
        os.mkdir(infoDirPath)
        os.mkdir(previousAttacksPath)
        advanceInformationJson = json.dumps(advanceInformation)
        advanceInformationFile = open(pathToSave, "w")
        advanceInformationFile.write(advanceInformationJson)
        advanceInformationFile.close()
        return ("IP Added", messageToUser)
    
# Permite crear la tabla que contiene información sobre el dispositivo, tanto en la parte de Shodan como la de fuerza bruta.
def createDeviceInfoTable(deviceInfo, comesFromShodan):
    table = QTableWidget(0,2)
    table.horizontalHeader().hide()
    table.verticalHeader().hide()
    table.setSizePolicy(QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Expanding)
    if comesFromShodan:
        # Se añade la información del sistema operativo si es necesario.
        if "os" in deviceInfo:
            if deviceInfo["os"] is not None:
                table.insertRow(table.rowCount())
                table.setItem(table.rowCount() - 1, 0, QTableWidgetItem("Os:"))
                table.setItem(table.rowCount() - 1, 1, QTableWidgetItem(deviceInfo['os']))
        # Se añade la información de los diversos servicios si es necesario.
        if "data" in deviceInfo:
            services = ""
            for i in range(len(deviceInfo['data'])):
                service = deviceInfo['data'][i]
                services += str(service['port']) + "/" + service['transport']
                if "product" in service:
                    services += "/" + service['product']
                if i % 3 == 2:
                    services += "<br>"
                else:
                    services += " || "
            services = services[:-4] 
            table.insertRow(table.rowCount())
            servicesItem = QLabel(services)
            table.setCellWidget(table.rowCount() - 1, 1, servicesItem)
            table.setItem(table.rowCount() - 1, 0, QTableWidgetItem("Ports:"))
        # Se añade la información de los diversos servicios si es necesario.
        if "tags" in deviceInfo:
            if len(deviceInfo["tags"]) != 0:
                table.insertRow(table.rowCount())
                table.setItem(table.rowCount() - 1, 0, QTableWidgetItem("Shodan tags:"))
                table.setItem(table.rowCount() - 1, 1, QTableWidgetItem(','.join(deviceInfo['tags'])))
        # Se añade la información de las vulnerabilidades si existen.
        if "vulns" in deviceInfo:
            vulnerabilities = ""
            for vuln in deviceInfo['vulns']:
                webToCheckDetails = "https://cvedetails.com/cve/"
                if "MS" in vuln:
                    webToCheckDetails = "https://www.cvedetails.com/microsoft-bulletin/"
                vulnerabilities += "<a href=\"" + webToCheckDetails + vuln + "/\">" + vuln + "</a><br>"
            vulnerabilities = vulnerabilities[:-4] 
            table.insertRow(table.rowCount())
            table.setItem(table.rowCount() - 1, 0, QTableWidgetItem("Vulnerabilities:"))
            vulnsItem = QLabel(vulnerabilities)
            vulnsItem.setOpenExternalLinks(True)
            table.setCellWidget(table.rowCount() - 1, 1, vulnsItem)
        # Se añade la información del pais del dispositivo.
        if "country_name" in deviceInfo:
            table.insertRow(table.rowCount())
            table.setItem(table.rowCount() - 1, 0, QTableWidgetItem("Country:"))
            table.setItem(table.rowCount() - 1, 1, QTableWidgetItem(deviceInfo['country_name']))
        # Se añade la información de la ciudad del dispositivo.
        if "city" in deviceInfo:
            table.insertRow(table.rowCount())
            table.setItem(table.rowCount() - 1, 0, QTableWidgetItem("City:"))
            table.setItem(table.rowCount() - 1, 1, QTableWidgetItem(deviceInfo['city']))
    else:
        nmapResults = list(deviceInfo['scan'].values())[0]
        osInfo = nmapResults['osmatch']
        if 'name' in osInfo:
            table.insertRow(table.rowCount())
            table.setItem(table.rowCount() - 1, 0, QTableWidgetItem("Os:"))
            table.setItem(table.rowCount() - 1, 1, QTableWidgetItem(osInfo['name']))
        tcpScan = nmapResults['tcp']
        services = ""
        for ip in tcpScan.keys():
            if tcpScan[ip]['state'] == "open":
                services += ip + "/" + tcpScan[ip]['name'] + "<br>"
        services = services[:-4] 
        portsOpen = QLabel(services)
        table.insertRow(table.rowCount())
        table.setCellWidget(table.rowCount() - 1, 1, portsOpen)
        table.setItem(table.rowCount() - 1, 0, QTableWidgetItem("Ports:"))  
    table.resizeColumnsToContents()
    table.resizeRowsToContents()
    return table

# Permite generar un Popup clásico en cualquier lugar de la aplicación.
def createPopup(self, title, content):
    # Generamos un popup con la información necesaria para el usuario
    infoPopup = QDialog(self)
    infoPopup.setWindowTitle(title)
    layout = QVBoxLayout()
    layout.addWidget(QLabel(content))
    closeButton = QDialogButtonBox(QDialogButtonBox.Ok)
    closeButton.accepted.connect(infoPopup.accept)
    layout.addWidget(closeButton)
    infoPopup.setLayout(layout)
    infoPopup.exec()

# Permite crear la ventana que muestra la información avanzada de un dispositivo, tanto en Shodan como en fuerza bruta.
def createAdvancedInfoPopup(self, neededIp):
    infoPopup = QDialog(self)
    infoPopup.setWindowTitle("Advanced Info " + neededIp)
    infoPopup.setMinimumSize(1280,720)
    layout = QVBoxLayout()
    advancedDataHtml = getHtmlAdvanceData(neededIp)
    textView = QTextBrowser()
    textView.setOpenLinks(False)
    textView.setContextMenuPolicy(Qt.ContextMenuPolicy.NoContextMenu)
    textView.setHtml(advancedDataHtml)
    searchBar = SearchBarWidget.SearchBarWidget(textView)
    layout.addWidget(searchBar)
    layout.addWidget(textView)
    closeButton = QDialogButtonBox(QDialogButtonBox.Ok)
    closeButton.accepted.connect(infoPopup.accept)
    layout.addWidget(closeButton)
    infoPopup.setLayout(layout)
    infoPopup.exec()

# Permite crear un pop up para mostrar el log de un ataque de fuerza bruta.
def createLogPopup(self, neededLogPath):
    infoPopup = QDialog(self)
    infoPopup.setWindowTitle("Log info")
    infoPopup.setMinimumSize(700,400)
    with open(neededLogPath,  "r") as logFile:
        logText = logFile.read()
    layout = QVBoxLayout()
    textView = QTextBrowser()
    textView.setOpenLinks(False)
    textView.setContextMenuPolicy(Qt.ContextMenuPolicy.NoContextMenu)
    textView.setText(logText)
    searchBar = SearchBarWidget.SearchBarWidget(textView)
    layout.addWidget(searchBar)
    layout.addWidget(textView)
    closeButton = QDialogButtonBox(QDialogButtonBox.Ok)
    closeButton.accepted.connect(infoPopup.accept)
    layout.addWidget(closeButton)
    infoPopup.setLayout(layout)
    infoPopup.exec()