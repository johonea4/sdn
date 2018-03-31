import sys
import os
import socket
import threading
from PyQt4.QtCore import pyqtSlot
from PyQt4.QtGui import *

# Test Firewall Server
# Sam Paulissian 
# create our window

if len(sys.argv) < 2:
     print ("\nUsage:  python fwqt-server.py <ip address>\n")
     sys.exit()

app = QApplication(sys.argv)
w = QWidget()
title = "Firewall Test Server " + str(sys.argv[1])
w.setWindowTitle(title)
txtresponse = '' 
# Create PortBox
portbox = QLineEdit(w)
portbox.move(20, 20)
portbox.resize(100,40)
l1 = QLabel(w)
l1.move (20,1)
l1.setText("Port")
rcvbox = QLineEdit(w)
rcvbox.move (80, 80)
rcvbox.resize(300,150)
 
# Set window size.
w.resize(420, 250)
 
# Create a button in the window
button = QPushButton('Listen', w)
button.move(160,20)
btnclose = QPushButton('Exit', w)
btnclose.move (260,20)

layout = QVBoxLayout(w)

b1 = QRadioButton("TCP")
b1.setChecked(True)
layout.addWidget(b1)
b2 = QRadioButton("UDP")
b2.setChecked(False)
layout.addWidget(b2)
blListen = True

# Create the actions
@pyqtSlot()
def on_click():
    msg = "Listening for a connection on "
    if b1.isChecked():
        msg = msg + "TCP port "
    else:
        msg = msg + "UDP port "
    msg = msg + portbox.text()
    rcvbox.setText(msg)
    blListen = False
    #thread1 = myThread(1)
    #thread1.start()
    prtListen = str(sys.argv[1]) + " " + str(portbox.text())
    if b1.isChecked():
        param = "python test-tcp-server.py " + prtListen + " &"
        print param
    else:
        param = "python test-udp-server.py " + prtListen + " &"
        print param
    os.system(param)
    

def on_exit():
    blListen = False
    sys.exit()

# connect the signals to the slots
button.clicked.connect(on_click)

btnclose.clicked.connect(on_exit) 
# Show the window and run the app

w.show()
app.exec_()

