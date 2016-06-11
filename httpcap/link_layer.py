from __future__ import unicode_literals, print_function, division

import struct
# see http://www.tcpdump.org/linktypes.html
# http://www.winpcap.org/ntar/draft/PCAP-DumpFileFormat.html#appendixLinkTypes
from httpcap.constant import NetworkProtocol
import six


class LinkLayer(object):
    """LinkType"""
    LINKTYPE_NULL = 0  # BSD loopback encapsulation
    ETHERNET = 1
    LINUX_SLL = 113

    @staticmethod
    def get_link_layer_parser(link_type):
        if link_type == LinkLayer.ETHERNET:
            return dl_parse_ethernet
        elif link_type == LinkLayer.LINUX_SLL:
            return dl_parse_linux_sll
        elif link_type == LinkLayer.LINKTYPE_NULL:
            return dl_parse_bsd_lo
        else:
            return None


# http://standards.ieee.org/about/get/802/802.3.html
def dl_parse_ethernet(link_packet):
    """ parse Ethernet packet """

    eth_header_len = 14
    # ethernet header
    ethernet_header = link_packet[0:eth_header_len]

    (network_protocol,) = struct.unpack(b'!12xH', ethernet_header)
    if network_protocol == NetworkProtocol.P802_1Q:
        # 802.1q, we need to skip two bytes and read another two bytes to get protocol/len
        type_or_len = link_packet[eth_header_len:eth_header_len + 4]
        eth_header_len += 4
        network_protocol, = struct.unpack(b'!2xH', type_or_len)
    if network_protocol == NetworkProtocol.PPPOE_SESSION:
        # skip PPPOE SESSION Header
        eth_header_len += 8
        type_or_len = link_packet[eth_header_len - 2:eth_header_len]
        network_protocol, = struct.unpack(b'!H', type_or_len)
    if network_protocol < 1536:
        # TODO n_protocol means package len
        pass
    return network_protocol, link_packet[eth_header_len:]


# http://www.tcpdump.org/linktypes/LINKTYPE_LINUX_SLL.html
def dl_parse_linux_sll(link_packet):
    """ parse linux sll packet """

    sll_header_len = 16

    # Linux cooked header
    linux_cooked = link_packet[0:sll_header_len]

    packet_type, link_type_address_type, link_type_address_len, link_type_address, network_protocol \
        = struct.unpack(b'!HHHQH', linux_cooked)
    return network_protocol, link_packet[sll_header_len:]


def dl_parse_bsd_lo(link_packet):
    """parse bsd loopback packet"""
    if len(link_packet) < 4:
        return None, None
    # first 4 bytes are packet size which always less then 256, may be LE or BE
    if six.byte2int(link_packet) == 0 and six.indexbytes(link_packet, 1) == 0:
        prot, = struct.unpack(b'>I', link_packet[:4])
    else:
        prot, = struct.unpack(b'<I', link_packet[:4])
    if prot > 0xFF:
        return None, None
    if prot == 2:
        network_protocol = NetworkProtocol.IP
    elif prot == 10:
        network_protocol = NetworkProtocol.IPV6
    else:
        return None, None
    return network_protocol, link_packet[4:]
