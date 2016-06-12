from __future__ import unicode_literals, print_function, division

from httpcap.constant import HttpType
from httpcap.httpparser import HttpParser
from httpcap.printer import HttpPrinter
from httpcap.content_utils import is_request

# assemble http packets

_max_seq = 0xFFFFFFFF
_seq_window = 2 << 20


def seq_compare(seq1, seq2):
    # if seq1 is behind seq2
    # return num > 0 if true, 0 if seq1 == seq2 , num < 0 if seq 2 behind seq1
    if seq1 > _max_seq - _seq_window and seq2 < _seq_window:
        seq2 += _max_seq
    elif seq1 < _seq_window and seq2 > _max_seq - _seq_window:
        seq1 += _max_seq

    return seq1 - seq2


class Stream(object):
    """one direction tcp stream"""

    def __init__(self):
        self.receive_buf = []
        self.status = 0
        self.last_ack_seq = -1

    def append_packet(self, packet):
        """
        :type packet:httpcap.packet_parser.TcpPack
        """
        if (seq_compare(packet.seq, self.last_ack_seq) >= 0 or self.last_ack_seq == -1) \
                and packet.body:
            self.receive_buf.append(packet)

    def retrieve_packet(self, ack_seq):
        if self.last_ack_seq != -1 and seq_compare(ack_seq, self.last_ack_seq) <= 0:
            return None

        self.last_ack_seq = ack_seq

        # if only one packet in window
        if len(self.receive_buf) == 1:
            if seq_compare(self.receive_buf[0].seq, ack_seq) < 0:
                data = self.receive_buf
                self.receive_buf = []
                return data
            else:
                return []

        # filter, sort, and remove duplicate packet
        data = []
        new_buf = []
        for packet in self.receive_buf:
            if seq_compare(packet.seq, ack_seq) < 0:
                data.append(packet)
            else:
                new_buf.append(packet)
        self.receive_buf = new_buf
        if len(data) <= 1:
            return data
        data.sort(key=lambda pct: pct.seq)
        new_data = []
        last_packet_seq = None
        for packet in data:
            if packet.seq != last_packet_seq:
                last_packet_seq = packet.seq
                new_data.append(packet)
        return new_data


class TcpConnection(object):
    def __init__(self, packet):
        """
        :type packet: httpcap.packet_parser.TcpPack
        """
        self.up_stream = Stream()
        self.down_stream = Stream()
        self.client_key = packet.source_key()

        self.is_http = None
        self.processor = HttpPrinter((packet.source, packet.source_port),
                                     (packet.dest, packet.dest_port))
        self.http_parser = HttpParser(self.processor)
        self.on_packet(packet)
        self.last_timestamp = packet.timestamp

    def on_packet(self, packet):
        """
        :type packet: httpcap.packet_parser.TcpPack
        """
        self.last_timestamp = packet.timestamp
        if self.is_http is None and packet.body:
            self.is_http = is_request(packet.body)

        if not self.is_http:
            return

        if packet.source_key() == self.client_key:
            send_stream = self.up_stream
            confirm_stream = self.down_stream
            pac_type = HttpType.RESPONSE
        else:
            send_stream = self.down_stream
            confirm_stream = self.up_stream
            pac_type = HttpType.REQUEST

        if len(packet.body) > 0:
            send_stream.append_packet(packet)
        if packet.syn:
            pass
        if packet.ack:
            packets = confirm_stream.retrieve_packet(packet.ack_seq)
            if packets:
                for packet in packets:
                    self.http_parser.data_received(pac_type, packet.body)
        if packet.fin or packet.rst:
            send_stream.status = 1

    def closed(self):
        return self.up_stream.status == 1 and self.down_stream.status == 1

    def finish(self):
        self.http_parser.finish()
