#coding=utf-8
from __future__ import unicode_literals, print_function, division
__author__ = 'dongliu'


class HttpType(object):
    REQUEST = 0
    RESPONSE = 1


# see http://www.tcpdump.org/linktypes.html
# http://www.winpcap.org/ntar/draft/PCAP-DumpFileFormat.html#appendixLinkTypes
class LinkLayerType(object):
    """LinkType"""
    ETHERNET = 1
    LINUX_SLL = 113


class NetworkProtocol(object):
    IP = 2048
    IPV6 = 34525
    # Virtual Bridged Local Area Networks
    P802_1Q = 33024


class TransferProtocol(object):
    TCP = 6


class BlockType(object):
    SECTION_HEADER = 0x0A0D0D0A
    INTERFACE_DESCRIPTION = 0x00000001
    PACKET = 0x00000002
    SIMPLE_PACKET = 0x00000003
    NAME_RESOLUTION = 0x00000004
    INTERFACE_STATISTICS = 0x00000005
    ENHANCED_PACKET = 0x00000006
    IRIG_TIMESTAMP = 0x00000007
    ARINC_429 = 0x00000008