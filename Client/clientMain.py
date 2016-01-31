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
    sys.path.insert(0, parentPath+'/Client/')
    sys.path.insert(0, parentPath+'/Utilities/')

# ****************************************

from socket import *
from Client import ExchangeDHCli
from Utilities import MessageUtils
from Utilities.Constants import *

''' This is an implementation of the EKE algorithm.
    Why a passphrase is needed:
    The passphrase is needed to encrypt the initial messages for the key derivation (to encrypt the
    public parameters of the client)
    When a key gets derived with DH algorithm then it is used as a session key. That's what makes this
    mechanism so strong. The shared passphrase is used only at the begining, and on every connection the DH
    derives a new session-key.
    For more info see the rfc's that define EKE '''




tcpSocket = socket(AF_INET, SOCK_STREAM)
tcpSocket.connect(ADDR)

while True:
    # make the key exchange
    # we can use it with a new passphrase if we don't want to use the PASSPHRASE defined in the Constants.py
    # * the value in the Constants.py can be changed if we don't want to put a passphrase as a parameter!
    # session_key = ExchangeDHCli.exchangeDHCli(tcpSocket, "HELLOWORLD") # with a new passphrase!


    session_key = ExchangeDHCli.exchangeDHCli(tcpSocket)

    # this is all that's needed to derive the key!
    ''' as an example is brought a simple echo program.
        The user inputs a message, the client encrypts it with the session key and then sends it to the server.
        The server decrypts it checks if it equals to 'quit' and if so it closes the connection.
        If the message is not quit it echoes the message to the client!
        The client checks if the message says 'quit' and if so it closes the socket. If not it just asks the
        user to send another message! '''

    if session_key is None:
        print("No key was derived! ")
        exit(1)
    else:
        print("Now we can send encrypted messages\n\n")
        message = MessageUtils.receive_encrypted_message(tcpSocket, session_key)
        print("Server: " + message)

        while True:
            mess = input("Type a message: ")
            MessageUtils.send_encrypted_message(tcpSocket, mess, session_key)
            response = MessageUtils.receive_encrypted_message(tcpSocket, session_key)
            if response == 'quit':
                print("\'quit\' detected, closing connection ... ")
                tcpSocket.close()
                break
            else:
                print("Server: ", response)

    break
