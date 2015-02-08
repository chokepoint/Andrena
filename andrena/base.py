#!/usr/bin/env python

"""Andrena base module.
Includes the main classes for serial interaction, client contexts, dispatchers,
exceptions, and debugging functions."""

# Required modules
from sys import exit
from struct import pack, unpack

# Compression
from zlib import compress

# Cryptography
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac

from DiffieHellman import DiffieHellman

# Work queues for incoming / outgoing packets
from Queue import Queue

# Xbee communication
from serial import Serial
from xbee import XBee

# Multithreading support
from threading import Thread

# Debug stuff
DEBUG_ENABLED = True

def INFO(data):
    if DEBUG_ENABLED:
        print "[+] %s" % data

def WARN(data):
    if DEBUG_ENABLED:
        print "[!] %s" % data

# Local imports
from packet import *
from streams import *

# Exports
__all__ = ["DEBUG_ENABLED", "WARN", "INFO", "InvalidPacket", "InvalidStream",
            "Communicator", "Dispatcher", "ClientCTX"]

# Custom exceptions
class InvalidPacket(Exception):
    pass

class InvalidStream(Exception):
    pass

class Communicator:
    """Main communication class handles serial connection with the XBee module.

    Arguments:
        device -- Path to serial device (default: /dev/tty01)
        baudrate -- Serial baudrate (default: 9600)

    All received packet data is placed into the rx_queue.
    Transmission is handled by _packet_sender function.
    """
    def __init__(self, device='/dev/ttyO1', baudrate=9600):
        self.device    = device
        self.baudrate  = baudrate
        self.kill      = False

        self.rx_queue  = Queue()
        self.tx_queue  = Queue()

        self.serial    = Serial(self.device, self.baudrate)
        self.xbee      = XBee(self.serial, callback=self._packet_handler)

        self.tx_thread = Thread(target=self._packet_sender, args=())
        self.tx_thread.daemon = True
        self.tx_thread.start()

    def _packet_handler(self, data):
        """Internal serial callback adds data to rx_queue. No return."""
        self.rx_queue.put(data)

    def _packet_sender(self):
        """Internal threaded packet transmission loop.

        Reads outgoing packets from tx_queue and sends them over serial.
        """
        while True:
            if self.kill:
                exit(1)
            packet = self.tx_queue.get()
            self.tx_queue.task_done()

            if len(packet) > 100:
                WARN("Trying to send too large of a packet: %d" % len(packet))
                continue
            self.xbee.tx(dest_addr=packet[:2], data=packet[2:])

    def send(self, data):
        """Add data packet to transmission queue. No return.

        Packet data must be properly formated.
        [2 byte dst_addr][payload]
        """
        self.tx_queue.put(data)

    def close(self):
        """Cleanup communication pipes and threads. No return."""
        self.xbee.halt()
        self.serial.close()
        self.kill = True

class Dispatcher(Thread):
    """Dispatching thread processes incoming data from communicator class

    Arguments:
        comm -- Communicator class instance
        clients -- List of ClientCTX objects
    """
    def __init__(self, comm, clients):
        Thread.__init__(self)
        self.comm    = comm
        self.clients = clients
        self.daemon  = True

    def addr_to_ctx(self, addr):
        """Return a client context given a remote address.

        Arguments:
            addr -- Raw address to be resolved. (example: "\x00\x01")
        Return:
            ClientCTX object or None
        """
        for client in self.clients:
            if client.addr == addr:
                return client
        return None

    def validate_packet(self, packet):
        """Cursory packet header validation and length check.

        Arguments:
            packet -- Raw string of packet data
        Returns:
            Tuple (andrena header, raw data payload)
        Exceptions:
            InvalidPacket -- Unable to parse header
        """
        if len(packet) < HEADER_SIZE:
            raise InvalidPacket("Length < %d" % HEADER_SIZE)
        # Unwrap header and validate packet type
        hdr  = header.parse(packet[:HEADER_SIZE])
        data = packet[HEADER_SIZE:]
        if hdr.type not in PACKET_TYPES:
            raise InvalidPacket("Invalid type: %x" % packet.type)
        elif len(data) != hdr.payload_length:
            raise InvalidPacket("Invalid Payload length. Expected %d." \
                                "Received %d" % (hdr.payload_length, len(data)))
        return (hdr, data)

    def run(self):
        """Data processing loop. Sends incoming data to proper client."""
        while True:
            packet = self.comm.rx_queue.get()
            self.comm.rx_queue.task_done()
            client = self.addr_to_ctx(packet['source_addr'])
            if not client:
                WARN("No context for client")
                continue

            # Unrwap and validate header
            try:
                hdr, data = self.validate_packet(packet['rf_data'])
            except InvalidPacket, e:
                WARN("Invalid packet received: %s" % e)
                continue
            client.recv(hdr, data)

class ClientCTX:
    """Client context class. Each agent and handler must have a unique context
    associated with their assigned src_address.

    Arguments:
        comm -- Communicator class instance
        compress -- Boolean, enable transmission compression (default: False)
        addr -- Client's source address. (default: \x00\x00)
        psk -- Preshared key for signing Diffie Hellman exchange (default: "")
        dh_callback -- Callback function called once DH exchange is complete.
    """
    def __init__(self, comm, compress=False, addr="\x00\x00", psk="",
                 dh_callback=None):
        self.compress    = compress
        self.addr        = addr
        self.last_iv     = 0x00
        self.last_seq    = 0x00
        self.comm        = comm
        self.streams     = []
        self.stream_cnt  = 0
        self.pub_key     = 0
        self._psk        = psk
        self.dh_callback = dh_callback
        self._secret     = ""
        if not self._secret:
            INFO("Calculating diffie hellman public key")
            self.dh = DiffieHellman()

    def encrypt(self, plaintext):
        """Encrypt packet data prior to transmission.

        Arguments:
            plaintext -- raw packet data to be sent.
        Returns:
            Tuple of (iv, ciphertext, tag)
        """
        from struct import pack
        self.last_iv += 1
        iv = pack(">Q", self.last_iv)
        encryptor = Cipher(algorithms.AES(self._secret), modes.GCM(iv,
                            min_tag_length=4),
                            backend=default_backend()).encryptor()
        ciphertext = encryptor.update(plaintext)+encryptor.finalize()
        return (self.last_iv, ciphertext, encryptor.tag)

    def decrypt(self, ciphertext, iv, tag):
        """Decrypt incoming packets.

        Arguments:
            ciphertext -- Raw packet payload
            iv -- Specified in the header as the seq num.
            tag -- Calculated HMAC (specified in the header)
        """
        decryptor = Cipher(algorithms.AES(self._secret), modes.GCM(iv, tag,
                            min_tag_length=4),
                            backend=default_backend()).decryptor()
        return decryptor.update(ciphertext)+decryptor.finalize()

    def agent_hello(self):
        """Initiate an agent_hello stream transaction"""
        if not self.dh:
            WARN("No diffie hellman object found")
            return

        self.gen_hello(PacketTypes.AGENT_HELLO)

    def handler_hello(self):
        """Initiate an agent_hello response"""
        if self.pub_key == 0:
            WARN("Haven't received public key from client")
            return

        self.gen_hello(PacketTypes.HANDLER_HELLO)

    def gen_hello(self, pkt_type):
        """Construct agent or handler hello packet and send it. No return."""
        buf = str(self.dh.publicKey)
        if len(buf) % 2 != 0:
            buf = "0"+buf
        buf = buf.decode('hex')

        # Chunkify data and send it
        chunks = self.payload_to_chunks("no_meta", buf)
        if pkt_type == PacketTypes.AGENT_HELLO:
            stream = AgentHello(self.next_stream(), self)
        else:
            stream = HandlerHello(self.next_stream(), self)
        stream.buffer = buf
        stream.meta = "no_meta"
        self.send(stream)

    def next_stream(self):
        """Returns integer of the next available stream id for outgoing packets.
        Recurse until we find a free value between 1 and 255.
        """
        while True:
            if self.stream_cnt < 0xff:
                self.stream_cnt += 1
            else:
                self.stream_cnt = 1
            for stream in self.streams:
                if stream.id == self.stream_cnt:
                    self.next_stream()
            return self.stream_cnt

    def sign_chunk(self, chunk):
        """Calculate SHA1HMAC of given chunk. Returns first four bytes of HMAC.

        Arguments:
            chunk -- Data used for calculation
        Return:
            Integer of calculated 4 byte HMAC.
        """
        sum = hmac.HMAC(self._psk, hashes.SHA1(), backend=default_backend())
        sum.update(chunk)
        final = sum.finalize()
        return int(unpack('>I', final[:4])[0])

    def send(self, stream):
        """Loop through the given chunk list and queue them up for sending.

        Arguments:
            stream -- Stream class instance
        Exceptions:
            TypeError -- Invalid argument
        """
        from construct import Container

        if not isinstance(stream, Stream):
            raise TypeError("Stream is not the correct object type")

        # TODO Remove stream once we receive an ACK.
        self.streams.append(stream)

        flags = Flags.NONE
        cnt   = 0

        INFO("Sending Stream.\t ID: %x.\t Type: %s" % (stream.id, \
                PacketTypes(stream.type).name))
        chunks = self.payload_to_chunks(stream.meta, stream.buffer)
        for chunk in chunks:
            if cnt == 0:
                flags |= Flags.INIT
                flags |= Flags.META
            else:
                flags = Flags.DATA
            if self.compress:
                flags |= Flags.COMPRESS
            if len(chunks)-1 == cnt:
                flags |= Flags.FINISH

            if not stream.type in (PacketTypes.AGENT_HELLO,
                                    PacketTypes.HANDLER_HELLO):
                (iv, ciphertext, tag) = self.encrypt(chunk)
                tag = int(unpack('>I', tag[:4])[0])
            else:
                tag = self.sign_chunk(chunk)
                ciphertext = chunk
            # Handle new streams Change from hard coded 0x01
            hdr = header.build(Container(type=stream.type, stream=stream.id,
                                flags=flags, payload_length=len(chunk),
                                sequence=self.last_iv, tag=tag))

            # Change below to simply add it to the dispatcher tx_queue
            self.comm.send(self.addr+hdr+ciphertext)
            cnt+=1
        # TODO Move this into an ACK callback.
        self.streams.remove(stream)

    def id_to_stream(self, id):
        """Given stream id, return ClientCTX.

        Arguments:
            id -- taken from header.stream
        Return:
            ClientCTX object.
        Exceptions:
            InvalidStream -- Stream id not found
        """
        for stream in self.streams:
            if stream.id == id:
                return stream
        raise InvalidStream("ID not found")

    def stream_complete(self, stream, buffer):
        """Remove stream from internal list.

        Arguments:
            stream -- Stream object context
            buffer -- Final stream of data from the stream
        Return:
            None
        """
        INFO("Stream complete. ID: %x" % stream.id)
        self.streams.remove(stream)
        stream = None

    def recv(self, hdr, data):
        """Receive callback to be called by the dispatcher. No return.

        Function processes incoming data and sends it to the appropriate
        stream context. If a stream context does not exist, one is created.
        Stream data is all processsed by the appropriate stream class.
        Packet validation of stream types is performed here.
        """
        from struct import pack
        try:
            # If we're initializing a key exchange, don't decrypt
            sequence = pack(">Q", hdr.sequence)
            tag      = pack(">I", hdr.tag)
            if hdr.sequence < self.last_seq:
                raise InvalidPacket("Invalid: Sequence < last_seq")
            elif hdr.type in (PacketTypes.AGENT_HELLO, PacketTypes.HANDLER_HELLO):
                packet = data
                if hdr.tag != self.sign_chunk(data):
                    raise InvalidPacket("Tag does not match. Check your PSK")
            else:
                packet = self.decrypt(data, sequence, tag)
            self.last_seq = hdr.sequence
        except Exception, e:
            WARN(e)
            return

        # Add stream processing
        try:
            stream = self.id_to_stream(hdr.stream)
        except InvalidStream:
            if not hdr.flags & Flags.INIT:
                WARN("Unknown stream ID %x without INIT flag." % hdr.stream)
                return
            INFO("New stream. ID: %x\t Type: %s" % (hdr.stream, \
                    PacketTypes(hdr.type).name))

            if hdr.type == PacketTypes.FILE_TRANSFER:
                stream = RxFileTransfer(hdr.stream, self)
            elif hdr.type == PacketTypes.AGENT_HELLO:
                stream = RxAgentHello(hdr.stream, self)
            elif hdr.type == PacketTypes.HANDLER_HELLO:
                stream = RxHandlerHello(hdr.stream, self)
            else:
                WARN("Stream type not implemented")
            self.streams.append(stream)

        stream.add_data(packet, hdr.flags)

    def payload_to_chunks(self, meta, data, n=86):
        """Chunkify data into sendable chunk sizes. Returns list of chunks.

        Arguments:
            meta -- Meta data associated with the stream
            data -- String of data to be sent in this stream
            n -- Number of bytes per chunk. Compensate for headers (default: 86)
        """
        if self.compress:
            data = compress(data, 9)
            meta = compress(meta, 9)
        chunks = [meta]
        for i in xrange(0, len(data), n):
            chunks.append(data[i:i+n])
        return chunks
