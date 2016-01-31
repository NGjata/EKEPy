import struct

import jsonpickle

from Utilities.Encryption import *


def send_one_message(socket, data):
    encoded_data = jsonpickle.encode(data)
    length = len(encoded_data)
    socket.sendall(struct.pack('!I', length))
    if socket.sendall(encoded_data.encode()):
        print("Message couldn't be sent!")
        return True
    else:
        return False


def recv_one_message(socket):
    lengthbuf = recvall(socket, 4)
    if not lengthbuf:
        return None
    else:
        length, = struct.unpack('!I', lengthbuf)
        data = recvall(socket, length)
        decoded_data = jsonpickle.decode(data.decode('utf-8'))
        return decoded_data


def recvall(socket, count):
    buffer = b''
    while count:
        new_buffer = socket.recv(count)
        if not new_buffer: return None
        buffer += new_buffer
        count -= len(new_buffer)
    return buffer


def send_encrypted_message(sock, message, encryption_key):
    encryption = Encryption(str(encryption_key))
    encoded_message = jsonpickle.encode(message)
    encrypted_message = encryption.encrypt(encoded_message)
    if send_one_message(sock, encrypted_message):
        return True
    else:
        return False


def receive_encrypted_message(socket, encryption_key):
    encrypted_message = recv_one_message(socket)
    encryption = Encryption(str(encryption_key))
    decrypted_message = encryption.decrypt(encrypted_message)
    decoded_message = jsonpickle.decode(decrypted_message.decode('utf-8'))
    return decoded_message
