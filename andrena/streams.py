#!/usr/bin/env python

__all__ = ["Stream", "FileTransfer", "RxFileTransfer", "AgentHello",
            "RxAgentHello", "HandlerHello", "RxHandlerHello"]

from zlib import decompress

from base import WARN, INFO
from packet import *

class Stream:
    """Stream object for handling all aspects of each stream type.
    Flags generally drive how the individual packets are handled.
    Callbacks should be setup for specific types."""
    def __init__(self, id, stream_type, callback=None):
        self.id       = id
        self.type     = stream_type
        self.meta     = ""
        self.buffer   = ""
        self.callback = callback
        self.compress = False

    def __repr__(self):
        return str(self.id)

    def __str__(self):
        return str(self.id)

    def add_data(self, data, flags=Flags.NONE):
        """Append the decrypted packet data to the stream buffer.
        No return.
        """
        if flags & Flags.META:
            if flags & Flags.COMPRESS:
                self.compress = True
                data = decompress(data)
            self.meta = self.meta + data
        elif flags & Flags.DATA or flags == Flags.NONE:
            self.buffer = self.buffer + data
        if flags & Flags.FINISH:
            if self.compress:
                    self.buffer = decompress(self.buffer)
            if self.callback:
                self.callback(self, self.buffer)

class FileTransfer(Stream):
    def __init__(self, id, client, callback=None):
        if not id:
            id = client.next_stream()
        Stream.__init__(self, id, PacketTypes.FILE_TRANSFER, callback)
        self.client = client

class RxFileTransfer(FileTransfer):
    def __init__(self, id, client):
        INFO("Incoming file transfer")
        FileTransfer.__init__(self, id, client, self.save_file)

    def save_file(self, stream, buffer):
        """Save the received file using meta as the filename.
        File will be saved into the configured directory.
        """
        if not self.meta:
            WARN("Unable to save file. No filename set in metadata")
            return

        out = open(self.meta, "w")
        out.write(buffer)
        out.close()
        INFO("Wrote %d bytes to %s" % (len(buffer), self.meta))
        self.client.stream_complete(self, "")

class AgentHello(Stream):
    def __init__(self, id, client, callback=None):
        Stream.__init__(self, id, PacketTypes.AGENT_HELLO, callback)
        self.client = client

class RxAgentHello(AgentHello):
    def __init__(self, id, client):
        INFO("Incoming AgentHello")
        AgentHello.__init__(self, id, client, self.set_pub_key)

    def set_pub_key(self, stream, buffer):
        """Set the remove DH public key. This requires a response
        using the HANDLER_HELLO packet type. Since the initiator
        is always considered the agent.
        """
        self.client.pub_key = long(buffer.encode('hex'))

        # Calculate the key
        self.client.dh.genKey(self.client.pub_key)
        self.client._secret = self.client.dh.key

        # Send response
        self.client.handler_hello()

        INFO("Negotiated secret")
        if self.client.dh_callback:
            self.client.dh_callback(self.client)
        self.client.stream_complete(self, "")

class HandlerHello(Stream):
    def __init__(self, id, client, callback=None):
        Stream.__init__(self, id, PacketTypes.HANDLER_HELLO, callback)
        self.client = client

class RxHandlerHello(HandlerHello):
    def __init__(self, id, client):
        INFO("Incoming HandlerHello")
        HandlerHello.__init__(self, id, client, self.set_priv_key)

    def set_priv_key(self, stream, buffer):
        """Callback function to set the private key to the newly calculated key."""
        temp_key = long(buffer.encode('hex'))

        # Calculate the key
        self.client.dh.genKey(temp_key)
        self.client._secret = self.client.dh.key
        INFO("Negotiated secret")
        if self.client.dh_callback:
            self.client.dh_callback(self.client)

        # Add send ack for validation
        self.client.stream_complete(self, "")
