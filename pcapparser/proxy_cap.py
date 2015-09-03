from __future__ import unicode_literals, print_function, division
from pcapparser.printer import HttpPrinter

__author__ = "dongliu"

import sys
import argparse
import socket
import select
import threading
import signal

from pcapparser.httpparser import HttpType, HttpParser
from pcapparser import config


_BUF_SIZE = 8192
_MAX_READ_RETRY_COUNT = 20
_READ_TIMEOUT = 3


class ConnectionHandler(object):
    """handle one connection from client"""

    def __init__(self, client_socket):
        self.client_socket = client_socket
        self.first_data = b''
        self.http_type = HttpType.REQUEST
        self.remote_host = None
        self.path = None
        self.method = None
        self.protocol = None
        self.target_socket = None

    def init_connect(self):
        end = -1
        while True:
            self.first_data += self.client_socket.recv(_BUF_SIZE)
            end = self.first_data.find(b'\n')
            if end != -1:
                break
        self.method, self.path, self.protocol = self.first_data[:end + 1].split()

        if self.method == b'CONNECT':
            self.first_data = self.first_data[end + 1:]
            self._method_connect()
        elif self.method in (b'OPTIONS', b'GET', b'HEAD', b'POST', b'PUT', b'DELETE', b'TRACE'):
            self._method_others()

    def close(self):
        self.client_socket.close()
        self.target_socket.close()

    def _method_connect(self):
        """for http proxy connect method. it is usually for https proxy"""
        self._connect_target(self.path)
        self.client_socket.send(
            b'HTTP/1.1 200 Connection established\nProxy-agent: Python Proxy\n\n')

    def _method_others(self):
        self.path = self.path[len(b'http://'):]
        i = self.path.find(b'/')
        if i > 0:
            host = self.path[:i]
        else:
            host = self.path
        self._connect_target(host)

    def _connect_target(self, host):
        i = host.find(b':')
        if i != -1:
            port_str = host[i + 1:]
            if port_str:
                port = int(host[i + 1:])
            else:
                port = 80
            host = host[:i]
        else:
            port = 80
        (soc_family, _, _, _, address) = socket.getaddrinfo(host, port)[0]
        self.remote_host = address
        self.target_socket = socket.socket(soc_family)
        self.target_socket.connect(address)

    def proxy_data(self, http_parser):
        """run the proxy"""
        self.target_socket.send(self.first_data)
        http_parser.send(HttpType.REQUEST, self.first_data)

        sockets = [self.client_socket, self.target_socket]
        empty_read_count = 0
        while True:
            empty_read_count += 1
            (data, _, error) = select.select(sockets, [], sockets, _READ_TIMEOUT)
            if error:
                # connection closed, or error occurred.
                break

            if not data:
                continue

            for in_ in data:
                try:
                    data = in_.recv(_BUF_SIZE)
                except ConnectionResetError as e:
                    break
                out = self.target_socket if in_ is self.client_socket else self.client_socket
                http_type = HttpType.REQUEST if in_ is self.client_socket else HttpType.RESPONSE
                if data:
                    out.send(data)
                    empty_read_count = 0
                    http_parser.send(http_type, data)

            if empty_read_count == _MAX_READ_RETRY_COUNT:
                break


def _worker(worker_socket, client_ip, client_port, output_file):
    try:
        handler = ConnectionHandler(worker_socket)
        handler.init_connect()
        processor = HttpPrinter((client_ip, client_port), handler.remote_host)
        http_parser = HttpParser(processor)
        handler.proxy_data(http_parser)
        handler.close()
        http_parser.finish()
    except Exception:
        import traceback

        traceback.print_exc()


def start_server(host='0.0.0.0', port=8000, IPv6=False, output=None):
    """start proxy server."""
    ip_version = IPv6 and socket.AF_INET6 or socket.AF_INET
    server_socket = socket.socket(ip_version)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server_socket.bind((host, port))
    except Exception as e:
        print(e)
        sys.exit(-1)
    print("Proxy start on %s:%d" % (host, port))
    server_socket.listen(0)

    output_file = open(output, "w+") if output else sys.stdout
    config.out = output_file

    def clean():
        """do clean job after process terminated"""
        try:
            server_socket.close()
        except:
            pass
        try:
            output_file.close()
        except:
            pass

    # when press Ctrl+C, stop the proxy.
    def signal_handler(signal, frame):
        print('\nStopping proxy...')
        clean()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    try:
        while True:
            worker_socket, client = server_socket.accept()
            (client_ip, client_port) = client
            worker_thread = threading.Thread(
                target=_worker,
                args=(worker_socket, client_ip, client_port, output_file)
            )
            worker_thread.setDaemon(True)
            worker_thread.start()
    finally:
        clean()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-l", "--listen",
                        help="the IP of the interface which the proxy listened on")
    parser.add_argument("-p", "--port", type=int,
                        help="the port of the interface which the proxy listened on")
    parser.add_argument("-6", "--ipv6", help="use ipv6", action="store_true")
    parser.add_argument("-v", "--verbosity", help="increase output verbosity(-vv is recommended)",
                        action="count")
    parser.add_argument("-g", "--group", help="group http request/response by connection",
                        action="store_true")
    parser.add_argument("-o", "--output", help="output to file instead of stdout")
    parser.add_argument("-e", "--encoding", help="decode the data use specified encodings.")
    parser.add_argument("-b", "--beauty", help="output json in a pretty way.", action="store_true")

    args = parser.parse_args()
    setting = {"IPv6": args.ipv6}
    if args.listen:
        setting["host"] = args.listen
    if args.port:
        setting["port"] = args.port
    if args.output:
        setting["output"] = args.output

    # output config
    parse_config = config.get_config()
    if args.verbosity:
        parse_config.level = args.verbosity
    if args.encoding:
        parse_config.encoding = args.encoding
    parse_config.pretty = args.beauty
    parse_config.group = args.group

    start_server(**setting)


if __name__ == '__main__':
    main()
