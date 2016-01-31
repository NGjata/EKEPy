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


def exchangeDHCli(socket, sharedPassphrase=PASSPHRASE):
    if VERBOSE_MODE:
        globalTimeStart = time.clock()
        print("\n \n Starting DH key derivation algorithm...")
        print("------------------------------------------")
        print('\nGenerating public keys... ')
        print("-> Generator: ", GENERATOR)
        print("-> Group (p): ", GROUP)
    else:
        print("Starting DH key derivation algorithm...\nPlease wait...")

    if MEASURE_TIME: start = time.clock()
    dhObjClient = DiffieHellman(GENERATOR, GROUP, KEY_LENGTH)
    A = dhObjClient.genPublicKey()
    if MEASURE_TIME: end = time.clock()

    if VERBOSE_MODE:
        print("-> A: ", A)
        if MEASURE_TIME:
            print("{0:.5f} sec".format(end - start))
        print('\n')
        print('Encrypting A with the passphrase... ')

    if MEASURE_TIME: start = time.clock()
    EncrObj = Encryption(sharedPassphrase)
    encryptedA = EncrObj.encrypt(jsonpickle.encode(A))
    if MEASURE_TIME: end = time.clock()

    message = {'Identity': 'ClientA', 'EncData': encryptedA.decode('utf-8'), 'Generator': GENERATOR, 'Group': GROUP}
    serialisedParameters = jsonpickle.encode(message)

    if VERBOSE_MODE:
        if MEASURE_TIME: print("{0:.5f} sec".format(end - start))
        print("\nSend packet to Server: ", serialisedParameters)
        print('\n')

    MessageUtils.send_one_message(socket, serialisedParameters)

    # We just sent:
    # message => {Identity, EncryptedData, Generator, Group(where the prime is found)}



    # receive Servers message!
    serversPubParams = MessageUtils.recv_one_message(socket)

    if VERBOSE_MODE:
        print("Packet received: ")

    if (not serversPubParams):
        if VERBOSE_MODE:
            print("-> Server responded with empty! ")
        return
    else:

        # we should have received Server's identity and the encrypted Tb + a random number

        serversIdentity = serversPubParams['Identity']
        serversEnc = serversPubParams['EncData']

        if VERBOSE_MODE:
            print("-> Identity: ", serversIdentity)
            print("-> EncData: ", serversEnc)
            print('\n')

        if MEASURE_TIME: start = time.clock()

        serversPar = EncrObj.decrypt(serversEnc)
        serversDecodedPar = jsonpickle.decode(serversPar.decode('utf-8'))

        if MEASURE_TIME: end = time.clock()

        Tb = serversDecodedPar['Tb']
        serverRandom = serversDecodedPar['ServerRandom']

        if VERBOSE_MODE:
            print("Decrypted EncData: ")
            print("-> Tb: ", Tb)
            print("-> ServerRandom: ", serverRandom)
            print("{0:.5f} sec".format(end - start))

        # generate the shared key
        if VERBOSE_MODE:
            print('\n')
            print("Deriving session key...")

        if MEASURE_TIME: start = time.clock()
        dhObjClient.genKey(Tb)
        derived_secret = str(dhObjClient.getKey())
        if MEASURE_TIME: end = time.clock()

        if VERBOSE_MODE:
            print("-> Derived Key: ", derived_secret)
            if MEASURE_TIME: print("{0:.5f} sec".format(end - start))
            print("\n\n *** Sending test data ***  \n\n ")

        # This is the Test Phase!
        clientRandomNumber = str(dhObjClient.genRandom(KEY_LENGTH))

        if VERBOSE_MODE:
            print("Choosing random number...")

        testMessage = {"ServerRandom": serverRandom, "ClientRandom": clientRandomNumber}

        serializeTestMessage = jsonpickle.encode(testMessage)

        if VERBOSE_MODE:
            print("Create packet: ", testMessage)

        if MEASURE_TIME: start = time.clock()
        newEncryption = Encryption(derived_secret)
        encryptedMessage = newEncryption.encrypt(serializeTestMessage)
        if MEASURE_TIME: end = time.clock()

        if VERBOSE_MODE:
            print("Encry. packet: ", encryptedMessage)
            if MEASURE_TIME:
                print("{0:.5f} sec\n".format(end - start))
            print("Send packet...\n")

        MessageUtils.send_one_message(socket, encryptedMessage)

        # receive the last response !


        serversMessage = MessageUtils.recv_one_message(socket)

        if VERBOSE_MODE:
            print("Encrypted Packet received: ", serversMessage)

        if MEASURE_TIME: start = time.clock()
        decryptServersMessage = newEncryption.decrypt(serversMessage)
        receivedRandom = decryptServersMessage.decode('utf-8')
        if MEASURE_TIME: end = time.clock()

        if VERBOSE_MODE:
            print("Decrypting Packet... ")
            if MEASURE_TIME:
                print("{0:.5f} sec \n".format(end - start))

        if (receivedRandom == clientRandomNumber):
            if VERBOSE_MODE:
                print("-> Sent random was: ", clientRandomNumber)
                print("-> Rec. random is : ", receivedRandom)
                print("\nThe randoms correspond!")

                globalTimeStop = time.clock()

                print(
                    "\n\n***** KEY DERIVATION COMPLETED in {0:.5f} sec *****".format(globalTimeStop - globalTimeStart))
                print("The session key is: ", hexlify(dhObjClient.getKey()))
                print("----------------------------------------------------------------------------------------\n\n")
            else:

                print("***** Key derivation completed *****")
            return dhObjClient.getKey()

        else:
            if VERBOSE_MODE:
                print("\nThe received random doesn't correspond to the one that was sent!")
                print("-> Sent random: ", clientRandomNumber)
                print("-> Rec. random: ", receivedRandom)
                print("\n\n***** KEY DERIVATION FAILED *****\n\n")
            else:

                print("***** KEY DERIVATION FAILED *****")
            return None
