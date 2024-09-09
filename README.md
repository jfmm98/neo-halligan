# Neo-halligan
Neo-Halligan is a brute force python project that merges Shodan python API and legba brute force tool with a GUI for ease of use. Although it development was focused on windows, it works on Linux too. It has been tested on Windows 11 and Kali Linux.

## Instructions to install

- Install python.
- Download the repository.
- Either uncompress the legba executable tool available on the zip file or build it from the source code (https://github.com/evilsocket/legba). If you decide to build it, the obtained executable must have the following protocols: AMQP, MQTT, FTP, SSH, HTTP, MongoDB and MySQL.
- On Linux you must give legba file the executable permission.
- If you want to add IPs manually (instead of using Shodan), you have to install nmap (https://nmap.org/download). 
- Install the packages available on the requirements.txt file. In order to do that, you can either do pip install -r path/requirements.txt or install them on a virtual environment so it will not be installed on your computer (https://packaging.python.org/en/latest/guides/installing-using-pip-and-virtual-environments/).
- In order to work on Linux, you must have installed gnome-terminal (if not installed) and libxcb-cursor-dev packages.
- Run the main.py file with python.
- On the app, if you want to use the shodan capabilities, you must have an account with at least a membership tier. That tier can be obtained for free if you have an academic email and you email the Shodan support. However, if you don't add a Shodan account key, you can manually add an IP and a nmap run will be done, but only for the default ports on the supported protocols listed above.
- On the How to use tab on the application you can have more information about the use of the different functionalities that Neo-Halligan offers.
