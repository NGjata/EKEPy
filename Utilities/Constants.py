# this settings are for the server and/or the client
# ---------------------------------------------------
''' some of these settings should be the same on the client and server! '''

HOST = "127.0.0.1"  # the host we are connecting to
PORT = 21442  # port
BUFSIZ = 1024  # size of socket's buffer
ADDR = (HOST, PORT)

PASSPHRASE = "NENSIGJATA"  # this is the default passphrase to use when encrypting the public parameters
# RANDOM_SPACE_SIZE = 4


KEY_LENGTH = 2048  # the length of DH key

# If VERBOSE MODE is False the DH won't output any debug data (transparent)
VERBOSE_MODE = True
'''Note that if VERBOSE_MODE is false
MEASURE_GLOBAL_TIME and MEASURE_TIME won't
have any effect on the output! '''
MEASURE_GLOBAL_TIME = True  # how much time does the all the DH algorithm take.
MEASURE_TIME = True  # how much time do the slowest algorithms take.

# these settings are choosen only by the client, have no effect on the server!
# -------------------------------------------------------------------------

GENERATOR = 2  # public generator
GROUP = 17  # public group (the prime number)
