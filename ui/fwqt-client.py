import sys
import os
import socket
import threading
from PyQt4.QtCore import pyqtSlot
from PyQt4.QtGui import *

# Test Firewall Client
# Sam Paulissian 
# create our window
app = QApplication(sys.argv)
w = QWidget()
w.setWindowTitle('Firewall Test Client')
txtresponse = '' 
# Create PortBox
portbox = QLineEdit(w)
portbox.move(20, 20)
portbox.resize(100,40)
ipbox = QLineEdit(w)
ipbox.move (160,20)
ipbox.resize(150,40)
l1 = QLabel(w)
l1.move (20,1)
l1.setText("Port")
l2 = QLabel(w)
l2.move (160,1)
l2.setText ("IP Address")
rcvbox = QLineEdit(w)
rcvbox.move (80, 80)
rcvbox.resize(300,150)
#rcvbox.setWordWrap(True)
 
# Set window size.
w.resize(420, 250)
 
# Create a button in the window
button = QPushButton('Send', w)
button.move(310,20)
btnclose = QPushButton('Exit', w)
btnclose.move (310,50)

layout = QVBoxLayout(w)

b1 = QRadioButton("TCP")
b1.setChecked(True)
layout.addWidget(b1)
b2 = QRadioButton("UDP")
b2.setChecked(False)
layout.addWidget(b2)

# Create the actions
@pyqtSlot()
def on_click():

    if b1.isChecked():
       txtproto = "TCP"
    else:
       txtproto = "UDP"
    rcvbox.setText("Sending..."+ txtproto +" Port " + str(portbox.text()) + " IP: " + str(ipbox.text()))
    txtresponse = ''
    #thread1 = myThread(1)
    #thread1.start()
    prtListen = str(ipbox.text()) + " " + str(portbox.text())
    if b1.isChecked():
        param = "python test-tcp-client.py " + prtListen + " &"
        print param
    else:
        param = "python test-udp-client.py " + prtListen + " &"
        print param
    os.system(param)
    print (txtresponse)

def on_exit():
    sys.exit()

# connect the signals to the slots
button.clicked.connect(on_click)

btnclose.clicked.connect(on_exit) 
# Show the window and run the app
w.show()
app.exec_()

