#coding=utf-8
from __future__ import unicode_literals, print_function, division

import threading
from collections import defaultdict
import sys

try:
    # python2
    from Queue import Queue
    from StringIO import StringIO
except:
    # python3
    from queue import Queue
    from io import StringIO
from pyhttpcap import textutils
from pyhttpcap.constant import HttpType
from pyhttpcap.config import OutputLevel
from pyhttpcap.reader import DataReader

__author__ = 'dongliu'


class HttpRequestHeader(object):
    def __init__(self):
        self.content_len = 0
        self.method = b''
        self.host = b''
        self.uri = b''
        self.transfer_encoding = b''
        self.content_encoding = b''
        self.content_type = b''
        self.gzip = False
        self.chunked = False
        self.expect = b''
        self.protocol = b''


class HttpResponseHeader(object):
    def __init__(self):
        self.content_len = 0
        self.status_line = None
        self.transfer_encoding = b''
        self.content_encoding = b''
        self.content_type = b''
        self.gzip = False
        self.chunked = False
        self.connection_close = False


class RequestMessage(object):
    """used to pass data between requests"""

    def __init__(self):
        self.expect_header = None


class HttpParser(object):
    """parse http req & resp"""

    def __init__(self, client_host, remote_host, parse_config):
        self.buf = StringIO()
        self.client_host = client_host
        self.remote_host = remote_host
        self.config = parse_config

        self.cur_type = None
        self.cur_data_queue = None
        self.inited = False
        self.is_http = False

        self.task_queue = None
        self.worker = None

    def send(self, http_type, data):
        if not self.inited:
            self._init(http_type, data)
            self.inited = True

        if not self.is_http:
            return

        if self.cur_type == http_type:
            self.cur_data_queue.put(data)
            return

        self.cur_type = http_type
        if self.cur_data_queue is not None:
            # finish last task
            self.cur_data_queue.put(None)
        # start new task
        self.cur_data_queue = Queue()
        self.cur_data_queue.put(data)
        self.task_queue.put((self.cur_type, self.cur_data_queue))

    def _init(self, http_type, data):
        if not textutils.is_request(data) or http_type != HttpType.REQUEST:
            # not a http request
            self.is_http = False
        else:
            self.is_http = True
            self.task_queue = Queue()  # one task is an http request or http response strem
            self.worker = threading.Thread(target=self.process_tasks, args=(self.task_queue,))
            self.worker.setDaemon(True)
            self.worker.start()

    def process_tasks(self, task_queue):
        self._line(('*' * 10 + " [%s:%d] -- -- --> [%s:%d] " + '*' * 10) %
                   (self.client_host[0], self.client_host[1], self.remote_host[0], self.remote_host[1]))

        message = RequestMessage()

        while True:
            httptype, data_queue = task_queue.get()
            if httptype is None:
                break

            reader = DataReader(data_queue)
            try:
                if httptype == HttpType.REQUEST:
                    self.read_request(reader, message)
                elif httptype == HttpType.RESPONSE:
                    self.read_response(reader, message)
                    self._line('')
            except Exception:
                import traceback

                traceback.print_exc()
                # consume all datas.
                reader.skipall()
                break

    def finish(self):
        if self.task_queue is not None:
            self.task_queue.put((None, None))
            if self.cur_data_queue is not None:
                self.cur_data_queue.put(None)
            self.worker.join()
        return self.buf.getvalue()

    def _line(self, line):
        if type(line) == type(b''):
            line = line.decode('utf-8')
        self.buf.write(line)
        self.buf.write('\n')

    def _lineif(self, level, line):
        if self.config.level >= level:
            self._line(line)

    def read_headers(self, reader):
        if sys.version < '3':
            header_dict = defaultdict(str)
        else:
            header_dict = defaultdict(bytes)
        while True:
            line = reader.readline()
            if line is None:
                break
            line = line.strip()
            if not line:
                break
            self._lineif(OutputLevel.HEADER, line)

            key, value = textutils.parse_http_header(line)
            if key is None:
                # incorrect headers.
                continue

            header_dict[key.lower()] = value
        return header_dict

    def read_http_req_header(self, reader):
        """read & parse http headers"""
        line = reader.readline()
        if line is None:
            return None
        line = line.strip()

        if not textutils.is_request(line):
            return None
        req_header = HttpRequestHeader()
        items = line.split(b' ')
        if len(items) == 3:
            req_header.method = items[0]
            req_header.uri = items[1]
            req_header.protocol = items[2]

        self._lineif(OutputLevel.HEADER, line)

        header_dict = self.read_headers(reader)
        if b"content-length" in header_dict:
            req_header.content_len = int(header_dict[b"content-length"])
        if b'chunked' in header_dict[b"transfer-encoding"]:
            req_header.chunked = True
        req_header.content_type = header_dict[b'content-type']
        req_header.gzip = (b'gzip' in header_dict[b"content-encoding"])
        req_header.host = header_dict[b"host"]
        if b'expect' in header_dict:
            req_header.expect = header_dict[b'expect']

        self._lineif(OutputLevel.HEADER, b'')

        if self.config.level == OutputLevel.ONLY_URL:
            if req_header.uri.startswith(b'http://'):
                self._line(req_header.method + b" " + req_header.uri)
            else:
                self._line(req_header.method + b" http://" + req_header.host + req_header.uri)
        return req_header

    def read_http_resp_header(self, reader):
        """read & parse http headers"""
        line = reader.readline()
        if line is None:
            return line
        line = line.strip()

        if not textutils.is_response(line):
            return None
        resp_header = HttpResponseHeader()
        resp_header.status_line = line

        self._lineif(OutputLevel.HEADER, line)

        header_dict = self.read_headers(reader)
        if b"content-length" in header_dict:
            resp_header.content_len = int(header_dict[b"content-length"])
        if b'chunked' in header_dict[b"transfer-encoding"]:
            resp_header.chunked = True
        resp_header.content_type = header_dict[b'content-type']
        resp_header.gzip = (b'gzip' in header_dict[b"content-encoding"])
        resp_header.connection_close = (header_dict[b'connection'] == b'close')

        self._lineif(OutputLevel.HEADER, '')

        if self.config.level == OutputLevel.ONLY_URL:
            self._line(resp_header.status_line)
        return resp_header

    def read_chunked_body(self, reader, skip=False):
        """ read chunked body """
        result = []
        # read a chunk per loop
        while True:
            # read chunk size line
            cline = reader.readline()
            if cline is None:
                # error occurred.
                if not skip:
                    return b''.join(result)
                else:
                    return
            chunk_size_end = cline.find(b';')
            if chunk_size_end < 0:
                chunk_size_end = len(cline)
                # skip chunk extension
            chunk_size_str = cline[0:chunk_size_end]
            # the last chunk
            if chunk_size_str[0] == b'0':
                # chunk footer header
                # TODO: handle additional http headers.
                while True:
                    cline = reader.readline()
                    if cline is None or len(cline.strip()) == 0:
                        break
                if not skip:
                    return b''.join(result)
                else:
                    return
                    # chunk size
            chunk_size_str = chunk_size_str.strip()
            try:
                chunk_len = int(chunk_size_str, 16)
            except:
                return b''.join(result)

            data = reader.read(chunk_len)
            if data is None:
                # skip all
                # error occurred.
                if not skip:
                    return b''.join(result)
                else:
                    return
            if not skip:
                result.append(data)

            # a CRLF to end this chunked response
            reader.readline()

    def write_body(self, content, gzipped, charset, form_encoded):
        if gzipped:
            content = textutils.ungzip(content)
        content = textutils.decode_body(content, charset)
        # if content and form_encoded and self.config.pretty:
        #     import urllib
        #     content = urllib.unquote(content)
        if content:
            if self.config.pretty:
                textutils.try_print_json(content, self.buf)
            else:
                self.buf.write(content)
            self._line('')
        self._line('')

    def read_request(self, reader, message):
        """ read and output one http request. """
        if message.expect_header and not textutils.is_request(reader.fetchline()):
            req_header = message.expect_header
            message.expect_header = None
        else:
            req_header = self.read_http_req_header(reader)
            if req_header is None:
                # read header error, we skip all data.
                self._line("{parse http request header error}")
                reader.skipall()
                return
            if req_header.expect:
                # it is expect:continue-100 post request
                message.expect_header = req_header

        mime, charset = textutils.parse_content_type(req_header.content_type)
        # usually charset is not set in http post
        output_body = self.config.level >= OutputLevel.ALL_BODY and not textutils.is_binary(mime) \
            or self.config.level >= OutputLevel.TEXT_BODY and textutils.is_text(mime)

        content = b''
        # deal with body
        if not req_header.chunked:
            if output_body:
                content = reader.read(req_header.content_len)
            else:
                reader.skip(req_header.content_len)
        else:
            content = self.read_chunked_body(reader)

        if not req_header.gzip:
            # if is gzip by content magic header
            # someone missed the content-encoding header
            req_header.gzip = textutils.gzipped(content)

        # if it is form url encode

        if output_body:
            #unescape www-form-encoded data.x-www-form-urlencoded
            if self.config.encoding and not charset:
                charset = self.config.encoding
            self.write_body(content, req_header.gzip, charset, mime and b'form-urlencoded' in mime)

    def read_response(self, reader, message):
        """
        read and output one http response
        """
        resp_header = self.read_http_resp_header(reader)
        if resp_header is None:
            self._line("{parse http response headers error}")
            reader.skipall()
            return

        if message.expect_header:
            if resp_header.status_code == 100:
                # expected 100, we do not read body
                reader.skipall()
                return

        # read body
        mime, charset = textutils.parse_content_type(resp_header.content_type)
        if self.config.encoding and not charset:
            charset = self.config.encoding

        output_body = self.config.level >= OutputLevel.ALL_BODY and not textutils.is_binary(mime) \
            or self.config.level >= OutputLevel.TEXT_BODY and textutils.is_text(mime)

        content = b''
        # deal with body
        if not resp_header.chunked:
            if resp_header.content_len == 0:
                if resp_header.connection_close:
                    # we can't get content length, so assume it till the end of data.
                    resp_header.content_len = 10000000
                else:
                    # we can't get content length, and is not a chunked body, we cannot do nothing, just read all data.
                    resp_header.content_len = 10000000
            if output_body:
                content = reader.read(resp_header.content_len)
            else:
                reader.skip(resp_header.content_len)
        else:
            #TODO: we could skip chunked data other than read into memory.
            content = self.read_chunked_body(reader)

        if output_body:
            self.write_body(content, resp_header.gzip, charset, False)