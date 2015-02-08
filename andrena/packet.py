#!/usr/bin/env python
"""Contains things like packet header structure, flags,
and packet specific enums."""

# Required modules
from construct import Container, UBInt8, UBInt32, Struct
from enum import IntEnum

__all__ = ["header", "HEADER_SIZE", "Flags", "PacketTypes", "PACKET_TYPES"]

header = Struct("packet",
    UBInt8("type"),
    UBInt8("stream"),
    UBInt8("flags"),
    UBInt8("payload_length"),
    UBInt32("sequence"),
    UBInt32("tag")
)
HEADER_SIZE   = 0x0c

class Flags(IntEnum):
    # Flag fields
    NONE     = 0X00
    ALL      = 0XFF
    INIT     = (1 << 0)
    DATA     = (1 << 1)
    FINISH   = (1 << 2)
    COMPRESS = (1 << 3)
    META     = (1 << 4)

class PacketTypes(IntEnum):
    """Packet types"""
    AGENT_HELLO   = 0X01
    HANDLER_HELLO = 0X02
    AGENT_ACK     = 0X03
    PING_REQUEST  = 0X04
    PING_REPLY    = 0X05
    FILE_TRANSFER = 0X06
    COMMAND       = 0X07
    ANNOUNCEMENT  = 0X08
    ACK           = 0x09

PACKET_TYPES = tuple(range(PacketTypes.AGENT_HELLO, PacketTypes.ANNOUNCEMENT+1))
