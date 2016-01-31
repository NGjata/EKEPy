"""
EKEPy - An EKE implementation in Python
Copyright (C) 2016 by Nensi Gjata

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

# Hack in case the imports don't work outside of the PyCharm IDE
import os, sys
parentPath = os.path.abspath("..")
if parentPath not in sys.path:
    sys.path.insert(0, parentPath)
    sys.path.insert(0, parentPath+'/Server/')
    sys.path.insert(0, parentPath+'/Utilities/')

# ****************************************

from socket import *
from Server import ExchangeDHServ
from Utilities import MessageUtils
from Utilities.Constants import *

serverSocket = socket(AF_INET, SOCK_STREAM)
serverSocket.bind(ADDR)
serverSocket.listen(5)

while True:
    print("Waitin for a client to connect... ")
    connectedClientSocket, addr = serverSocket.accept()
    print("Connected client: ", addr)
    session_key = None

    while True:
        if not session_key:

            # when ExchangeDHServ finishes we will have a session key!
            # we can use it with a new passphrase if we don't want to use the PASSPHRASE defined in the Constants.py
            # * the value in the Constants.py can be changed if we don't want to put a passphrase as a parameter!
            # session_key = ExchangeDHCli.exchangeDHCli(tcpSocket, "HELLOWORLD") # with a new passphrase!
            # this is what is needed to derive a key!
            session_key = ExchangeDHServ.exchangeDHServ(connectedClientSocket)

            # now we can use the key as we want!
            ''' as an example is brought a simple echo program!
                the server gets the messages from the client, decrypts them and if the message says quit
                the server responds to the client and then closes the socket
                the client receives quit and closes his socket. '''

            if session_key == None:
                # if Diffie-Hellman didn't offer a key!
                print("No key derived! ")
                connectedClientSocket.close()
                exit(1)

            else:
                print("Now we can send encrypted messages! ")
                message1 = "Hi. This is the server. You can send me messages securely now and i will eco back! If you want to quit just type \'quit\'"
                MessageUtils.send_encrypted_message(connectedClientSocket, message1, session_key)

                while True:
                    receivedMessage = MessageUtils.receive_encrypted_message(connectedClientSocket, session_key)
                    if receivedMessage != 'quit':
                        MessageUtils.send_encrypted_message(connectedClientSocket, receivedMessage, session_key)
                    else:
                        print("\'quit\' detected, closing connection!")
                        MessageUtils.send_encrypted_message(connectedClientSocket, receivedMessage, session_key)
                        connectedClientSocket.close()
                        break

        break

    break



