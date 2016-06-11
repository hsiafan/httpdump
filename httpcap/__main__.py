# coding=utf8
from __future__ import unicode_literals, print_function, division

import argparse
import io
import signal
import sys

from httpcap import config
from httpcap import live_cap
from httpcap.parse_pcap import parse_pcap_file, run_parser


# when press Ctrl+C
def signal_handler(signal, frame):
    print("Canceled, stopping....", file=sys.stderr)
    sys.exit(0)


signal.signal(signal.SIGINT, signal_handler)


def parse_pcap():
    parse_("file")


def parse_live():
    parse_("device")


def parse_(source):
    parser = argparse.ArgumentParser()
    parser.add_argument("infile", nargs='?', help="the pcap file to parse")
    parser.add_argument("-i", "--ip", help="only parse packages with specified source OR dest ip")
    parser.add_argument("-p", "--port", type=int,
                        help="only parse packages with specified source OR dest port")
    parser.add_argument("-v", "--verbosity", help="increase output verbosity(-vv is recommended)",
                        action="count")
    parser.add_argument("-g", "--group", help="group http request/response by connection",
                        action="store_true")
    parser.add_argument("-o", "--output", help="output to file instead of stdout")
    parser.add_argument("-e", "--encoding", help="decode the data use specified encodings.")
    parser.add_argument("-b", "--beauty", help="output json in a pretty way.", action="store_true")
    parser.add_argument("-d", "--domain", help="filter http data by request domain")
    parser.add_argument("-u", "--uri", help="filter http data by request uri pattern")

    args = parser.parse_args()

    file_path = "-" if args.infile is None else args.infile

    _filter = config.get_filter()
    _filter.ip = args.ip
    _filter.port = args.port
    _filter.domain = args.domain
    _filter.uri_pattern = args.uri

    filter_exp = 'tcp'
    if args.port:
        filter_exp += " port " + str(args.port)
    if args.ip:
        filter_exp = "host " + args.ip + " and " + filter_exp

    # deal with configs
    parse_config = config.get_config()
    if args.verbosity:
        parse_config.level = args.verbosity
    if args.encoding:
        parse_config.encoding = args.encoding
    parse_config.pretty = args.beauty
    parse_config.group = args.group

    if args.output:
        output_file = open(args.output, "w+")
    else:
        output_file = sys.stdout

    config.out = output_file

    try:
        if source == 'file':
            infile = None
            try:
                if live_cap.has_pcap() and file_path != '-' and False:
                    # now slow than pure python version...
                    print("Use libpcap to pcap file, filter: {}".format(filter_exp),
                          file=sys.stderr)
                    producer = live_cap.libpcap_produce(filename=file_path, filter_exp=filter_exp)
                else:
                    if file_path != '-':
                        infile = io.open(file_path, "rb")
                    else:
                        infile = sys.stdin
                    producer = parse_pcap_file(infile)
                run_parser(producer)
            finally:
                if infile is not None:
                    infile.close()
        elif source == 'device':
            if not live_cap.has_pcap():
                print("Libpcap not found, install it first", file=sys.stderr)
            print("Capture device: {}, filter: {}".format(args.infile, filter_exp), file=sys.stderr)
            producer = live_cap.libpcap_produce(device=args.infile, filter_exp=filter_exp)
            run_parser(producer)
    finally:
        if args.output:
            output_file.close()


if __name__ == "__main__":
    parse_live()
