#coding=utf-8

__author__ = 'dongliu'


# see http://www.tcpdump.org/linktypes.html
# http://www.winpcap.org/ntar/draft/PCAP-DumpFileFormat.html#appendixLinkTypes
class LinkLayerType(object):
    """LinkType"""
    ETHERNET = 1
    LINUX_SLL = 113


class NetworkProtocal(object):
    IP = 2048
    IPV6 = 34525
    # Virtual Bridged Local Area Networks
    P802_1Q = 33024


class TransferProtocal(object):
    TCP = 6