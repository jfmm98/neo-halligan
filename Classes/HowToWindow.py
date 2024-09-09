from PySide6.QtWebEngineWidgets import QWebEngineView
from PySide6.QtWidgets import *
from PySide6.QtCore import *

# Esta clase permite mostrar al usuario como usar la aplicación.
class HowToWindow(QWidget):
    
    toggle = QComboBox()
    shodanHowTo = QWebEngineView()
    appHowTo = QTextBrowser()
    bruteforceHowTo = QTextBrowser()
    guidesLayout = QStackedLayout()

    # Se define el constructor de la clase. En este, se crean y gestionan los diversos elementos de la interfaz.
    def __init__(self, parent):
        super().__init__()
        self.toggle.addItems(["Neo-Halligan", "Shodan queries examples", "Shodan queries filters", "Brute force module"])
        appInstructions = """<h2>App Instructions</h2>
                            <p style="font-size: 14px">Neo-Halligan brings the unexperienced people at Shodan and brute force attacks the chance to learn about them, 
                            providing a GUI for ease of use. If you dont need the Shodan queries capabilities and wants to do a brute force attack on a specific target,
                            you can add manually that device IP on the corresponding tab. However, if you want to brute force devices from Shodan, then first you
                            need to add a Shodan key on the corresponding tab. After that, you can search the devices using the Shodan queries syntax (examples and filters
                            available up there). Those queries will spend your query credits on Shodan, so you should be aware about it. 
                            Finally, you can add the found devices and then do the brute force on the ports needed.</p>
                            """
        self.appHowTo.setText(appInstructions)
        self.appHowTo.setAlignment(Qt.AlignmentFlag.AlignTop)
        bruteforceInstructions = """<h2>Brute force instructions</h2>
                                    <p style="font-size: 14px">After adding ips via Shodan or manually, now you are able to do brute force attacks. In order to do it,
                                    you should check first if there are protocols on the target device that can be attacked by the tool. Those protocols are mqtt, amqp,
                                    http, fttp, ssh, mongodb and mysql.</p>
                                    <p><b>If your device has the advanced device info tab, is good to check all the information available for the port that you will brute force.</b></p>
                                    <h2>Global options</h2>
                                    <p style="font-size: 14px">First of all, you have to select the protocol to brute force and the port to do so. You can conveniently check
                                    the device information first in order to check which port runs the protocol that you are interested on bruteforce. Following that,
                                    all the protocols need to select usernames and password to check on the brute force process. You can either select a specific 
                                    username/password or check a whole wordlist. In order to do so, you must select the specific value/wordlist and then click the add button. </p>
                                    <h2>Extra options</h2>
                                    <p style="font-size: 14px">Some protocols have extra options, and some of them must be added (such as url on http protocol). Below
                                    you can check the extra options for each protocol that have them:</p>
                                    <h3>AMQP</h3>
                                    <p style="font-size: 14px">
                                    <ul>Activate SSL: It will activate the SSL protocol on the AMQP brute force.</ul>
                                    <h3>MQTT</h3>
                                    <p style="font-size: 14px">
                                    <ul>Mqtt v5: It will activate the 5 version of the protocol in order to do the brute force.</ul>
                                    <ul>Mqtt client id: It will the id for the tool when doing the brute force. <b>The default value is legba</b></ul>
                                    <h3>SSH</h3>
                                    <p style="font-size: 14px">
                                    <ul>Ssh auth mode: It will be the authentication mode for the brute force tool. If the key value is selected, then the specific password or wordlist must be keys instead of passwords.  
                                    <b>The default value is password</b></ul>
                                    <ul>Ssh key passphrase: Optional value that will be used if the authentication mode is key. It will a passphrase for the key authentication.</ul>
                                    <h3>HTTP</h3>
                                    <b>In http brute force, the ip and port won't be automatically selected. You MUST add the url to bruteforce like http://ip:port/restofurl</b>
                                    <ul>Authentication: It will be the authentication method used by the brute force tool. If requests is selected, it will do simple requests instead of using authentication
                                    such as basic, ntlm1 or ntlm2.</ul>
                                    <ul>Http method: It will be the method used for the tool when doing the brute force. It could be either GET or POST.</ul>
                                    <ul>URL to brute force: It will the target url for the brute force module. <b>It must be filled.</b></ul>
                                    <ul>Ntlm domain: If the authentication ntlm1 or ntlm2 is selected, then this will tell the target domain.</ul>
                                    <ul>Ntlm workstation: If the authentication ntlm1 or ntlm2 is selected, then this will tell the target workstation.</ul>
                                    <ul>Payload: It will be the payload sent while doing the brute force. The following is a payload example for a wordpress wp-login.php page: log={USERNAME}&pwd={PASSWORD}.
                                    The {USERNAME} and {PASSWORD} values will be replaces by the values provided by you.</ul>
                                    <ul>String to check: It will check the response obtained for a specific string. If that string is on the response, then it means that the user/pass combo pair was successful.</ul>
                                    </p>
                                    """
        self.bruteforceHowTo.setText(bruteforceInstructions)
        self.bruteforceHowTo.setAlignment(Qt.AlignmentFlag.AlignTop)
        self.guidesLayout.addWidget(self.appHowTo)
        self.guidesLayout.addWidget(self.shodanHowTo)
        self.guidesLayout.addWidget(self.bruteforceHowTo)
        self.guidesLayout.setAlignment(Qt.AlignmentFlag.AlignTop)
        self.guidesLayout.setCurrentIndex(0)
        howtoLayout = QVBoxLayout()
        self.toggle.currentIndexChanged.connect(lambda b=self: self.changeGuide())         
        howtoLayout.addWidget(self.toggle)
        howtoLayout.addLayout(self.guidesLayout)
        self.setLayout(howtoLayout)
        self.setWindowTitle("Neo-Halligan how to")

    # Permite mostrar la guía según el elemento indicado en el combobox.
    def changeGuide(self):
        currentValue = self.toggle.currentText()
        if currentValue == "Neo-Halligan":
            self.guidesLayout.setCurrentIndex(0)
        if currentValue == "Shodan queries examples":
            self.shodanHowTo.setUrl("https://www.shodan.io/search/examples")
            self.guidesLayout.setCurrentIndex(1)
        if currentValue == "Shodan queries filters":
            self.shodanHowTo.setUrl("https://www.shodan.io/search/filters")
            self.guidesLayout.setCurrentIndex(1)
        if currentValue == "Brute force module":
            self.guidesLayout.setCurrentIndex(2)