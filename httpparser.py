#coding=utf-8
from constant import HttpType

__author__ = 'dongliu'

from Queue import Queue
import threading
import StringIO
from config import OutputLevel
import textutils
from reader import DataReader, ResetableWrapper
from collections import defaultdict


class HttpRequestHeader(object):
    def __init__(self):
        self.content_len = 0
        self.method = ''
        self.host = ''
        self.uri = ''
        self.transfer_encoding = ''
        self.content_encoding = ''
        self.content_type = ''
        self.gzip = False
        self.chunked = False
        self.expect = ''
        self.protocal = ''


class HttpReponseHeader(object):
    def __init__(self):
        self.content_len = 0
        self.status_code = ''
        self.protocal = ''
        self.transfer_encoding = ''
        self.content_encoding = ''
        self.content_type = ''
        self.gzip = False
        self.chunked = False
        self.connectionclose = False


class HttpParser(object):
    """parse http req & resp"""
    def __init__(self, client_host, remote_host, parse_config):
        self.buf = StringIO.StringIO()
        self.client_host = client_host
        self.remote_host = remote_host
        self.config = parse_config
        self.queue = Queue()

        self.worker = self._start()

    def send(self, data):
        self.queue.put(data)

    def _work(self):
        self.buf.write(('*' * 10 + " [%s:%d] -- -- --> [%s:%d] " + '*' * 10 +  "\n") %
                       (self.client_host[0], self.client_host[1], self.remote_host[0], self.remote_host[1]))

        request_status = {}
        wrapper = ResetableWrapper(self.queue)
        try:
            while wrapper.remains():
                wrapper.settype(HttpType.REQUEST)
                reader = DataReader(wrapper.next_stream())
                if reader.fetchline() is None:
                    break
                self.read_request(reader, request_status)

                wrapper.settype(HttpType.RESPONSE)
                reader = DataReader(wrapper.next_stream())
                if not wrapper.remains():
                    self.buf.write('{Http response missing}\n\n')
                    break
                if reader.fetchline() is None:
                    self.buf.write('{Http response missing}\n\n')
                    break
                self.read_response(reader, request_status)
                self.buf.write('\n')
        except Exception as e:
            import traceback

            traceback.print_exc(file=self.buf)
            # consume all datas.
            # for proxy mode, make sure http-proxy works well
            while True:
                httptype, data = self.queue.get(block=True, timeout=None)
                if data is None:
                    break

    def _start(self):
        worker = threading.Thread(target=self._work)
        worker.setDaemon(True)
        worker.start()
        return worker

    def finish(self):
        self.queue.put((None, None))
        self.worker.join()
        return self.buf.getvalue()

    def _line(self, line):
        self.buf.write(line)
        self.buf.write('\n')

    def _lineif(self, level, line):
        if self.config.level >= level:
            self.buf.write(line)
            self.buf.write('\n')

    def read_headers(self, reader):
        header_dict = defaultdict(str)
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

        if not textutils.ishttprequest(line):
            return None
        req_header = HttpRequestHeader()
        items = line.split(' ')
        if len(items) == 3:
            req_header.method = items[0]
            req_header.uri = items[1]
            req_header.protocal = items[2]

        self._lineif(OutputLevel.HEADER, line)

        header_dict = self.read_headers(reader)
        if "content-length" in header_dict:
            req_header.content_len = int(header_dict["content-length"])
        if 'chunked' in header_dict["transfer-encoding"]:
            req_header.chunked = True
        req_header.content_type = header_dict['content-type']
        req_header.gzip = ('gzip' in header_dict["content-encoding"])
        req_header.host = header_dict["host"]
        if 'expect' in header_dict:
            req_header.expect = header_dict['expect']

        self._lineif(OutputLevel.HEADER, '')

        if self.config.level == OutputLevel.ONLY_URL:
            if req_header.uri.startswith('http://'):
                self.buf.write(req_header.method + " " + req_header.uri)
            else:
                self.buf.write(req_header.method + " http://" + req_header.host +  req_header.uri)
            self.buf.write('\n')
        return req_header


    def read_http_resp_header(self, reader):
        """read & parse http headers"""
        line = reader.readline()
        if line is None:
            return line
        line = line.strip()

        if not textutils.ishttpresponse(line):
            return None
        resp_header = HttpReponseHeader()
        items = line.split(' ')
        if len(items) == 3:
            resp_header.status_code = items[1]
            resp_header.protocal = items[0]

        self._lineif(OutputLevel.HEADER, line)

        header_dict = self.read_headers(reader)
        if "content-length" in header_dict:
            resp_header.content_len = int(header_dict["content-length"])
        if 'chunked' in header_dict["transfer-encoding"]:
            resp_header.chunked = True
        resp_header.content_type = header_dict['content-type']
        resp_header.gzip = ('gzip' in header_dict["content-encoding"])
        resp_header.connectionclose = (header_dict['connection'] == 'close')

        self._lineif(OutputLevel.HEADER, '')

        if self.config.level == OutputLevel.ONLY_URL:
            self.buf.write(resp_header.status_code)
            self.buf.write('\n')
        return resp_header

    def read_chunked_body(self, reader, skip=False):
        """ read chunked body """
        result = []
        # read a chunk per loop
        while True:
            # read chunk size line
            cline = reader.readline()
            if cline is None:
                # error ocurred.
                if not skip:
                    return ''.join(result)
                else:
                    return
            chunk_size_end = cline.find(';')
            if chunk_size_end < 0:
                chunk_size_end = len(cline)
                # skip chunk extension
            chunk_size_str = cline[0:chunk_size_end]
            # the last chunk
            if chunk_size_str[0] == '0':
                # chunk footer header
                # todo: handle additional http headers.
                while True:
                    cline = reader.readline()
                    if cline is None or len(cline.strip()) == 0:
                        break
                if not skip:
                    return ''.join(result)
                else:
                    return
                    # chunk size
            chunk_size_str = chunk_size_str.strip()
            try:
                chunk_len = int(chunk_size_str, 16)
            except:
                return ''.join(result)

            data = reader.read(chunk_len)
            if data is None:
                # skip all
                # error ocurred.
                if not skip:
                    return ''.join(result)
                else:
                    return
            if not skip:
                result.append(data)

            # a CRLF to end this chunked response
            reader.readline()

    def _body(self, content, gzipped, charset, form_encoded):
        if gzipped:
            content = textutils.ungzip(content)
        content = textutils.decode_body(content, charset)
        if content and form_encoded and self.config.pretty:
            import urllib

            content = urllib.unquote(content)
        if content:
            if self.config.pretty:
                textutils.try_print_json(content, self.buf)
            else:
                self.buf.write(content)
        else:
            self.buf.write("{empty body}")
        self.buf.write('\n\n')


    def read_request(self, reader, request_status):
        """ read and output one http request. """
        if 'expect' in request_status and not textutils.ishttprequest(reader.fetchline()):
            req_header = request_status['expect']
            del request_status['expect']
        else:
            req_header = self.read_http_req_header(reader)
            if req_header is None:
                self._line("{Error, cannot parse http request headers.}")
                reader.skipall()
                return
            if req_header.expect:
                # assume it is expect:continue-100
                request_status['expect'] = req_header

        mime, charset = textutils.parse_content_type(req_header.content_type)
        # usually charset is not set in http post
        output_body = self.config.level >= OutputLevel.ALL_BODY and not textutils.isbinarybody(mime) \
            or self.config.level >= OutputLevel.TEXT_BODY and textutils.istextbody(mime)

        content = ''
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
            req_header.gzip = textutils.isgzip(content)

        # if it is form url encode

        if 'expect' in request_status and not content:
            content = '{Expect-continue-100, see next content for http post body}'
        if output_body:
            #unescape www-form-encoded data.x-www-form-urlencoded
            if self.config.encoding and not charset:
                charset = self.config.encoding
            self._body(content, req_header.gzip, charset, mime and 'form-urlencoded' in mime)

    def read_response(self, reader, request_status):
        """
        read and output one http response
        """
        resp_header = self.read_http_resp_header(reader)
        if resp_header is None:
            self._line("{Error, cannot parse http response headers.}")
            reader.skipall()
            return

        # read body
        mime, charset = textutils.parse_content_type(resp_header.content_type)
        if self.config.encoding and not charset:
            charset = self.config.encoding

        output_body = self.config.level >= OutputLevel.ALL_BODY and not textutils.isbinarybody(mime) \
            or self.config.level >= OutputLevel.TEXT_BODY and textutils.istextbody(mime)

        content = ''
        # deal with body
        if not resp_header.chunked:
            if resp_header.content_len == 0:
                if resp_header.connectionclose:
                    # we can't get content length, so asume it till the end of data.
                    #TODO: add readall method
                    resp_header.content_len = 10000000L
                else:
                    #TODO: we can't get content length, and is not a chunked body.
                    pass
            if output_body:
                content = reader.read(resp_header.content_len)
            else:
                reader.skip(resp_header.content_len)
        else:
            #TODO: could skip chunked data.
            content = self.read_chunked_body(reader)

        if output_body:
            self._body(content, resp_header.gzip, charset, False)