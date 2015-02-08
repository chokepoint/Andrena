# Andrena
Simple multi-stream protocol for use with ZigBee wireless modules. Adds an additional layer of encryption and allows advanced streams such as file transfers.

## Overview
I have a few particular needs for my current use of the ZigBee protocol. None of which were currently implemented by anything that is publicly available. Instead of relying on serial type data connectivity between nodes, I needed to be able to transfer files, issue commands to other modules etc. This project is the beginning of my work in this area.

Prior to transferring any stream types, the Handler and Agent must mutually authenticate using a Diffie-Hellman key exchange. The key exchange packets are signed using an existing pre shared key between the modules. This provides forward secrecy for communication, and doesn't compromise the entire network if a module goes missing. Pre shared keys should be unique between each module pair that is comunicating.

## Packet format
The packet header was intentionally kept small due to the length restrictions on ZigBee packets. The total packet length is restricted to 100 bytes (minus two byte destination header, and the 12 byte Andrena header below). This means that we a maximum of 86 byte payload per packet. The python module splits up byte streams into appropriate chunk sizes and sends them as streams to the remote clients.
```
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+---------------------------------------------------------------+
|      Type     |   Stream Id   |      Flags    |     Length    |
+---------------------------------------------------------------+
|                             Seq Num                           |
+---------------------------------------------------------------+
|                               Tag                             |
+---------------------------------------------------------------+
|                             Payload...                        |
+---------------------------------------------------------------+
```

### Stream Types
```
  AGENT_HELLO   = 0X01 # Implemented
  HANDLER_HELLO = 0X02 # Implemented
  AGENT_ACK     = 0X03
  PING_REQUEST  = 0X04
  PING_REPLY    = 0X05
  FILE_TRANSFER = 0X06 # Implemented
  COMMAND       = 0X07
  ANNOUNCEMENT  = 0X08
  ACK           = 0x09
```

### Seq Num
Counter IV for AES encryption, also helps keep streams in sync. 

### Tag
Sha1 HMAC of each packet. Diffie Hellman exchanges are HMACed with the pre shared key between clients to protect against man in the middle attacks.

## Example
Included in the examples folder is a handler and an agent. The agent connects to the handler, initiates the DH key exchange, and upon successful negotiation sends the README.md file to the handler. You obviously need two XBee modules for this to work. Ensure the PSK for the client contexts match otherwise the DH exchange will fail.

## Disclaimer
I am neither a full time developer, nor a cryptographer. If you see any issues with either of these, please submit a pull request. This is still very much experimental technology, and in pre-alpha stages as most of the protocol is still not implemented. Use at your own risk.
