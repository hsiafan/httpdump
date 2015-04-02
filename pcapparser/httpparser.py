from __future__ import unicode_literals, print_function, division

from collections import defaultdict

from pcapparser import utils
from pcapparser.constant import HttpType, Compress
from pcapparser.reader import DataReader
from pcapparser import config


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
        self.expect = b''
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


class RequestMessage(object):
    """used to pass data between requests"""

    def __init__(self):
        self.expect_header = None
        self.filtered = False


class HttpParser(object):
    """parse http req & resp"""

    def __init__(self, processor):
        """
        :type processor: HttpDataProcessor
        """
        self.cur_type = None
        self.inited = False
        self.is_http = False
        self.worker = None
        self.processor = processor

        self.cur_data = None
        self.message = RequestMessage()

    def send(self, http_type, data):
        if not self.inited:
            self._init(http_type, data)
            self.inited = True

        if not self.is_http:
            return

        # still current http request/response
        if self.cur_type == http_type:
            self.cur_data.append(data)
            return

        if self.cur_data is not None:
            reader = DataReader(self.cur_data)
            if self.cur_type == HttpType.REQUEST:
                self.read_request(reader, self.message)
            elif self.cur_type == HttpType.RESPONSE:
                self.read_response(reader, self.message)

        self.cur_type = http_type

        # new http request/response
        self.cur_data = []
        self.cur_data.append(data)

    def _init(self, http_type, data):
        if not utils.is_request(data) or http_type != HttpType.REQUEST:
            # not a http request
            self.is_http = False
        else:
            self.is_http = True

    def finish(self):
        # if still have unprocessed data
        if self.cur_data:
            reader = DataReader(self.cur_data)
            if self.cur_type == HttpType.REQUEST:
                self.read_request(reader, self.message)
            elif self.cur_type == HttpType.RESPONSE:
                self.read_response(reader, self.message)

    def read_headers(self, reader, lines):
        """
        :type reader: DataReader
        :type lines: list
        :return: dict
        """
        header_dict = defaultdict(str)
        while True:
            line = reader.read_line()
            if line is None:
                break
            line = line.strip()
            if not line:
                break
            lines.append(line)

            key, value = utils.parse_http_header(line)
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
        if not utils.is_request(line):
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
        req_header.compress = utils.get_compress_type(header_dict[b"content-encoding"])
        req_header.host = header_dict[b"host"]
        if b'expect' in header_dict:
            req_header.expect = header_dict[b'expect']

        req_header.raw_data = b'\n'.join(lines)
        return req_header

    def read_http_resp_header(self, reader):
        """read & parse http headers"""
        line = reader.read_line()
        if line is None:
            return line
        line = line.strip()

        if not utils.is_response(line):
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
        resp_header.compress == utils.get_compress_type(header_dict[b"content-encoding"])
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

    def read_request(self, reader, message):
        """ read and output one http request. """
        if message.expect_header and not utils.is_request(reader.fetch_line()):
            req_header = message.expect_header
            message.expect_header = None
        else:
            req_header = self.read_http_req_header(reader)
            if req_header is None:
                # read header error, we skip all data.
                reader.skip_all()
                return
            if req_header.expect:
                # it is expect:continue-100 post request
                message.expect_header = req_header

        # deal with body
        if not req_header.chunked:
            content = reader.read(req_header.content_len)
        else:
            content = self.read_chunked_body(reader)

        _filter = config.get_filter()
        show = _filter.by_domain(req_header.host) and _filter.by_uri(req_header.uri)
        message.filtered = not show
        if show:
            self.processor.on_http_req(req_header, content)

    def read_response(self, reader, message):
        """
        read and output one http response
        """
        resp_header = self.read_http_resp_header(reader)
        if resp_header is None:
            reader.skip_all()
            return

        if message.expect_header:
            if resp_header.status_code == 100:
                # expected 100, we do not read body
                reader.skip_all()
                return

        # read body
        if not resp_header.chunked:
            if resp_header.content_len == 0:
                if resp_header.connection_close:
                    # we can't get content length, so assume it till the end of data.
                    resp_header.content_len = 10000000
                else:
                    # we can't get content length, and is not a chunked body, we cannot do nothing,
                    # just read all data.
                    resp_header.content_len = 10000000
            content = reader.read(resp_header.content_len)
        else:
            content = self.read_chunked_body(reader)

        if not message.filtered:
            self.processor.on_http_resp(resp_header, content)