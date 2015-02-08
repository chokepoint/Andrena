#!/usr/bin/env python

import andrena

# Setup communication handler
comm = andrena.Communicator(device="/dev/ttyUSB0")

# Define ACL for remote clients that we can talk to
agent = andrena.ClientCTX(comm=comm, addr="\x00\x02", psk="A"*16)

# Setup dispatcher to process messages from the communicator
dispatch = andrena.Dispatcher(comm=comm, clients=[agent])
dispatch.start()

try:
    from time import sleep
    while True:
        sleep(5)
except KeyboardInterrupt:
    print "Got ^c"
    comm.close()

