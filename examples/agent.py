#!/usr/bin/env python

import andrena

def got_key(client):
    # Setup callback for when diffie hellman key is negotiated
    infile = open('README.md', 'r')
    data = infile.read()
    infile.close()

    stream = andrena.FileTransfer(None, client)
    stream.meta = "newreadme" # save file remotely as newreadme
    stream.buffer = data
    client.send(stream)

# Setup communicator object using default serial port
comm = andrena.Communicator(device='/dev/ttyUSB1')

# Setup a remote client (the handler) ctx
handler = andrena.ClientCTX(comm, addr="\x00\x01", psk="A"*16, dh_callback=got_key)

# Create a message processor for the comm object
dispatch = andrena.Dispatcher(comm=comm, clients=[handler])
dispatch.start()

# Initiate DiffieHellman key exchange
handler.agent_hello()

try:
    from time import sleep
    while True:
        sleep(5)
except KeyboardInterrupt:
    comm.close()
    sys.exit(0)
