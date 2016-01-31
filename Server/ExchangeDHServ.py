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
    sys.path.insert(0, parentPath+'/Utilities/')

# ****************************************

import time
import jsonpickle
from Utilities import MessageUtils
from Utilities.Constants import *
from Utilities.DiffieHellman import *
from Utilities.Encryption import *


# Exchange of Diffie-Hellman keys
# default passphrase is the one defined in the Constats.py
def exchangeDHServ(socket, sharedPassphrase=PASSPHRASE):




    if VERBOSE_MODE:
        globalTimeStart = time.clock()
        print("\n \n Starting DH key derivation algorithm...")
        print("------------------------------------------")
    else:
        print("Starting DH key derivation algorithm...\nPlease wait...")

    clientPubParams = MessageUtils.recv_one_message(socket)

    if VERBOSE_MODE:
        print("\nPacket received: ")

    if not clientPubParams:
        if VERBOSE_MODE:
            print("-> Client responded with empty! ")
        return
    else:
        if VERBOSE_MODE:
            print("-> Packet: ", clientPubParams)

        decodedClientMessage = jsonpickle.decode(clientPubParams)

        # we got some data:
        clientsIdentity = decodedClientMessage['Identity']
        encryptedData = decodedClientMessage['EncData']
        clientGenerator = decodedClientMessage['Generator']
        clientGroup = decodedClientMessage['Group']

        if VERBOSE_MODE:
            print('\n')
            print("Compacting Received Data: ")
            print("-> Identity: ", clientsIdentity)
            print("-> EncData: ", encryptedData)
            print("-> Generator: ", clientGenerator)
            print("-> Group: ", clientGroup)

        # we should decrypt the encrypted value
        if VERBOSE_MODE:
            print('\n')
            print("Decrypting EncData (extracting Ta) ...")

        if MEASURE_TIME: start = time.clock()
        EncrObj = Encryption(sharedPassphrase)
        decryptedData = EncrObj.decrypt(encryptedData)
        if MEASURE_TIME: end = time.clock()

        Ta = jsonpickle.decode(decryptedData.decode('utf-8'))

        if VERBOSE_MODE:
            print("-> Ta: ", Ta)
            print("{0:.5f} sec".format(end - start))


            # now we got all the data so we can derive the key

        if MEASURE_TIME: start = time.clock()
        dhObjServer = DiffieHellman(clientGenerator, clientGroup, KEY_LENGTH)
        dhObjServer.genKey(Ta)
        derived_secret = str(dhObjServer.getKey())
        if MEASURE_TIME: end = time.clock()

        if VERBOSE_MODE:
            print('\n')
            print("Derived key: ", derived_secret)
            print("{0:.5f} sec".format(end - start))

        if MEASURE_TIME:
            start = time.clock()

        Tb = dhObjServer.genPublicKey()

        if VERBOSE_MODE:
            print("Calculated Tb: ", Tb)
            if MEASURE_TIME:
                end = time.clock()
            print("{0:.5f} sec\n".format(end - start))

        # now let's notify the client we got the request!

        serverRandomNumber = str(dhObjServer.genRandom(KEY_LENGTH))

        if VERBOSE_MODE:
            print("Extracting ServerRandom: ", serverRandomNumber)

        messageEnc = {'Tb': Tb, 'ServerRandom': serverRandomNumber}

        serialiseMess = jsonpickle.encode(messageEnc)

        if VERBOSE_MODE:
            print('\n')
            print("Encrypting EncData={Tb,ServerRandom}")

        if MEASURE_TIME: start = time.clock()
        encryptedMess = EncrObj.encrypt(serialiseMess)
        if MEASURE_TIME: end = time.clock()

        sendMessage = {'Identity': 'Server', 'EncData': encryptedMess}
        if VERBOSE_MODE:
            print("-> EncData: ", encryptedMess)
            if MEASURE_TIME:
                print("{0:.5f} sec\n".format(end - start))

        serialiseSendMessage = sendMessage

        if VERBOSE_MODE:
            print('\n')
            print("Send packet to the client: ", serialiseSendMessage)

        MessageUtils.send_one_message(socket, serialiseSendMessage)

        if VERBOSE_MODE:
            print("Packet sent! ")

        # second phase completed! now we should test the derived key

        if VERBOSE_MODE:
            print("\n\n *** Waiting for test data ***  \n\n ")

        clientMessage = MessageUtils.recv_one_message(socket)

        if VERBOSE_MODE:
            print("Received an encrypted packet:  ", clientMessage)
            print("Decrypting packet with the derived key...")

        if MEASURE_TIME: start = time.clock()
        newEncryption = Encryption(derived_secret)
        decryptMessage = newEncryption.decrypt(clientMessage)
        if MEASURE_TIME: end = time.clock()

        decodeMessage = jsonpickle.decode(decryptMessage.decode('utf-8'))
        receivedRandom = decodeMessage['ServerRandom']
        getClientRandom = decodeMessage['ClientRandom']

        if VERBOSE_MODE:
            print("\n")
            print("Decrypted packet: ")
            print("-> ServerRandom (c1): ", receivedRandom)
            print("-> ClientRandom (c2): ", getClientRandom)
            print("{0:.5f} sec\n".format(end - start))
            print("\n")

        if (receivedRandom == serverRandomNumber):

            if VERBOSE_MODE:
                print("Sent random: ", serverRandomNumber)
                print("Rec. random: ", receivedRandom)
                print("The randoms correspond!")
                print("Encrypting and sending the client's random Ek(C2)... ")

            if MEASURE_TIME: start = time.clock()
            encryptClientRandom = newEncryption.encrypt(getClientRandom)
            MessageUtils.send_one_message(socket, encryptClientRandom)

            if VERBOSE_MODE:
                if MEASURE_TIME:
                    end = time.clock()
                    print("{0:.5f} sec\n".format(end - start))

            if VERBOSE_MODE:
                globalTimeStop = time.clock()
                print(
                    "\n\n***** KEY DERIVATION COMPLETED in {0:.5f} sec *****".format(globalTimeStop - globalTimeStart))
                print("The session key is: ", hexlify(dhObjServer.getKey()))
                print("----------------------------------------------------------------------------------------\n\n")

            else:
                print("***** Key derivation completed *****")

            return dhObjServer.getKey()

        else:
            if VERBOSE_MODE:
                print("The received random doesn't correspond to the one that was sent!")
                print("Sent random: ", serverRandomNumber)
                print("Rec. random: ", receivedRandom)
                print("\n\n***** KEY DERIVATION FAILED *****\n\n")
            else:
                print("***** KEY DERIVATION FAILED *****")

            return None
