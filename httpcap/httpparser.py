from __future__ import unicode_literals, print_function, division

import threading
from collections import defaultdict

import six

from httpcap import content_utils
from httpcap.constant import HttpType, Compress
from httpcap.reader import DataReader
from httpcap import config

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
        self.compress = Compress.IDENTITY
        self.chunked = False
        self.expect = False
        self.protocol = b''
        self.raw_data = None


class HttpResponseHeader(object):
    def __init__(self):
        self.content_len = 0
        self.status_line = None
        self.status_code = None
        self.transfer_encoding = b''
        self.content_encoding = b''
        self.content_type = b''
        self.compress = Compress.IDENTITY
        self.chunked = False
        self.connection_close = False
        self.raw_data = None


class RequestContext(object):
    """used to pass data between requests"""

    def __init__(self):
        self.expect_header = None  # for save expect-100 continue
        self.filtered = False
        self.support_expect = False
        self.next_resp_header = False


class HttpParser(object):
    """parse http req & resp"""

    def __init__(self, processor):
        """
        :type processor: HttpDataProcessor
        """
        self.inited = False
        self.is_http = False
        self.worker = None
        self.processor = processor
        self.request_reader = None
        self.response_reader = None

    def data_received(self, http_type, data):
        if not self.inited:
            self._init(http_type, data)
            self.inited = True

        if not self.is_http:
            # current connection is not http connection, just skip all data
            return
        if not data:
            return
        if self.worker.done:
            return

        if http_type == HttpType.REQUEST:
            self.request_reader.send_data(data)
        elif http_type == HttpType.RESPONSE:
            self.response_reader.send_data(data)

    def _init(self, http_type, data):
        """
        Called when receive first packet. do init jobs
        """
        if not content_utils.is_request(data) or http_type != HttpType.REQUEST:
            # not a http request
            self.is_http = False
        else:
            self.is_http = True

        # start parser worker
        self.request_reader = DataReader()  # request data
        self.response_reader = DataReader()  # response data
        worker = HttpParserWorker(self.request_reader, self.response_reader, self.processor)
        worker.setName("Http parser worker")
        # worker.setDaemon(True)
        worker.start()
        self.worker = worker

    def finish(self):
        # if still have unprocessed data
        if self.request_reader:
            self.request_reader.send_finish()
        if self.response_reader:
            self.response_reader.send_finish()


class HttpParserWorker(threading.Thread):
    # may be we need two threads?
    def __init__(self, request_reader, response_reader, processor):
        super(HttpParserWorker, self).__init__()
        self.request_reader = request_reader
        self.response_reader = response_reader
        self.processor = processor
        self.request_context = RequestContext()
        self.done = False

    def run(self):
        context = self.request_context
        while True:
            if not self.read_request(self.request_reader, context):
                self.done = True
                break

            if context.expect_header:
                # deal with expect-100. server may return 100, or 417 if not support,
                # or just timeout...
                if not self.read_response(self.response_reader, context):
                    self.done = True
                    break
                if not context.support_expect:
                    self.processor.on_http_req(self.request_context.expect_header, b'')
                    context.expect_header = None
                    continue
                context.support_expect = False
                if not self.read_request(self.request_reader, context):
                    self.done = True
                    break

            if not self.read_response(self.response_reader, self.request_context):
                self.done = True
                break
        self.request_reader.skip_all()
        self.response_reader.skip_all()

    def read_request(self, reader, context):
        """ read and output one http request. """
        if context.expect_header:
            # we are reading expect-100 body
            req_header = context.expect_header
            context.expect_header = None
        else:
            req_header = self.read_http_req_header(reader)
            if req_header is None:
                # reader finished, or error occurred, we skip all data.
                reader.skip_all()
                return False
            if req_header.expect:
                # it is expect:continue-100 request. save header for next body read
                context.expect_header = req_header
                return True
        # deal with body
        if not req_header.chunked:
            content = reader.read(req_header.content_len)
        else:
            content = self.read_chunked_body(reader)

        _filter = config.get_filter()
        show = _filter.by_domain(req_header.host) and _filter.by_uri(req_header.uri)
        context.filtered = not show
        if show:
            self.processor.on_http_req(req_header, content)
        return True

    def read_response(self, reader, context):
        """
        read and output one http response
        """
        if context.next_resp_header:
            resp_header = context.next_resp_header
            context.next_resp_header = None
        else:
            resp_header = self.read_http_resp_header(reader)
            if resp_header is None:
                # reader finished, or error occurred, we skip all data.
                reader.skip_all()
                return False

            if context.expect_header:
                if resp_header.status_code == 100:
                    # expected 100, we do not read body
                    context.support_expect = True
                elif resp_header.status_code == 417:
                    # not support
                    context.support_expect = False
                else:
                    # we think it is timeout, client continue send request body, and the server
                    #  return the real response. Cache this header, read request body first
                    context.support_expect = True
                    context.next_resp_header = resp_header
                    return True

        # read body
        if not resp_header.chunked:
            if resp_header.content_len == 0:
                if resp_header.connection_close:
                    # we can't get content length, so assume it till the end of data.
                    resp_header.content_len = 1000000000
                else:
                    # we can't get content length, and is not a chunked body, we cannot do nothing,
                    # just think content_len is 0
                    pass
            content = reader.read(resp_header.content_len)
        else:
            content = self.read_chunked_body(reader)

        if not context.filtered:
            self.processor.on_http_resp(resp_header, content)
        return True

    def read_headers(self, reader, lines):
        """
        :type reader: httpcap.reader.DataReader
        :type lines: list
        :rtype : dict
        :return: headers in dict
        """
        header_dict = defaultdict(six.binary_type)
        while True:
            line = reader.read_line()
            if line is None:
                break
            line = line.strip()
            if not line:
                break
            lines.append(line)

            key, value = content_utils.parse_http_header(line)
            if key is None:
                # incorrect headers.
                continue

            header_dict[key.lower()] = value
        return header_dict

    def read_http_req_header(self, reader):
        """read & parse http headers"""
        line = reader.read_line()
        if line is None:
            return None
        line = line.strip()
        if not content_utils.is_request(line):
            return None

        req_header = HttpRequestHeader()
        items = line.split(b' ')
        if len(items) == 3:
            req_header.method = items[0]
            req_header.uri = items[1]
            req_header.protocol = items[2]

        lines = [line]
        header_dict = self.read_headers(reader, lines)
        if b"content-length" in header_dict:
            req_header.content_len = int(header_dict[b"content-length"])
        if b"transfer-encoding" in header_dict and b'chunked' in header_dict[b"transfer-encoding"]:
            req_header.chunked = True
        req_header.content_type = header_dict[b'content-type']
        req_header.compress = content_utils.get_compress_type(header_dict[b"content-encoding"])
        req_header.host = header_dict[b"host"]
        if b'expect' in header_dict:
            # we only deal with 100-continue now...
            if b'100-continue' in header_dict[b'expect']:
                req_header.expect = True

        req_header.raw_data = b'\n'.join(lines)
        return req_header

    def read_http_resp_header(self, reader):
        """read & parse http headers"""
        line = reader.read_line()
        if line is None:
            return line
        line = line.strip()

        if not content_utils.is_response(line):
            return None
        resp_header = HttpResponseHeader()
        resp_header.status_line = line
        try:
            resp_header.status_code = int(line.split(' ')[1])
        except:
            pass

        lines = [line]
        header_dict = self.read_headers(reader, lines)
        if b"content-length" in header_dict:
            resp_header.content_len = int(header_dict[b"content-length"])
        if b"transfer-encoding" in header_dict and b'chunked' in header_dict[b"transfer-encoding"]:
            resp_header.chunked = True
        resp_header.content_type = header_dict[b'content-type']
        resp_header.compress == content_utils.get_compress_type(header_dict[b"content-encoding"])
        resp_header.connection_close = (header_dict[b'connection'] == b'close')
        resp_header.raw_data = b'\n'.join(lines)
        return resp_header

    def read_chunked_body(self, reader, skip=False):
        """ read chunked body """
        result = []
        # read a chunk per loop
        while True:
            # read chunk size line
            cline = reader.read_line()
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
                    cline = reader.read_line()
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

            # a CR-LF to end this chunked response
            reader.read_line()
