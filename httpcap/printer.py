from __future__ import unicode_literals, print_function, division

from io import StringIO
import sys

from httpcap.config import OutputLevel
# print http req/resp
from httpcap import content_utils
from httpcap import config
import threading
import six
from httpcap.constant import Compress
from httpcap.content_utils import Mime

_printer_lock = threading.Lock()


def _get_full_url(uri, host):
    if uri.startswith(b'http://') or uri.startswith(b'https://'):
        return uri
    else:
        return b'http://' + host + uri


class HttpPrinter(object):
    def __init__(self, client_host, remote_host):
        self.parse_config = config.get_config()
        self.buf = StringIO()
        self.client_host = client_host
        self.remote_host = remote_host

    def on_http_req(self, req_header, req_body):
        """
        :type req_header: HttpRequestHeader
        :type req_body: bytes
        """
        if self.parse_config.level == OutputLevel.ONLY_URL:
            self._println(req_header.method + b" " + _get_full_url(req_header.uri, req_header.host))
        elif self.parse_config.level == OutputLevel.HEADER:
            self._println(req_header.raw_data)
            self._println()
        elif self.parse_config.level >= OutputLevel.TEXT_BODY:
            self._println(req_header.raw_data)
            self._println()

            mime, charset = content_utils.parse_content_type(req_header.content_type)
            # usually charset is not set in http post
            output_body = self._if_output(mime)
            if self.parse_config.encoding and not charset:
                charset = self.parse_config.encoding
            if req_header.compress == Compress.IDENTITY:
                # if is gzip by content magic header
                # someone missed the content-encoding header
                if content_utils.gzipped(req_body):
                    req_header.compress = Compress.GZIP
            if output_body:
                self._print_body(req_body, req_header.compress, mime, charset)
                self._println('')

    def on_http_resp(self, resp_header, resp_body):
        """
        :type resp_header: HttpResponseHeader
        :type resp_body: bytes
        """
        if self.parse_config.level == OutputLevel.ONLY_URL:
            self._println(resp_header.status_line)
        elif self.parse_config.level == OutputLevel.HEADER:
            self._println(resp_header.raw_data)
            self._println()
        elif self.parse_config.level >= OutputLevel.TEXT_BODY:
            self._println(resp_header.raw_data)
            self._println()

            mime, charset = content_utils.parse_content_type(resp_header.content_type)
            # usually charset is not set in http post
            output_body = self._if_output(mime)
            if self.parse_config.encoding and not charset:
                charset = self.parse_config.encoding
            if resp_header.compress == Compress.IDENTITY:
                # if is gzip by content magic header
                # someone missed the content-encoding header
                if content_utils.gzipped(resp_body):
                    resp_header.compress = Compress.GZIP
            if output_body:
                self._print_body(resp_body, resp_header.compress, mime, charset)
                self._println()

        if not config.get_config().group:
            self._do_output()

    def finish(self):
        """called when this connection finished"""
        self._do_output()

    def _do_output(self):
        _printer_lock.acquire()
        try:
            value = self.buf.getvalue()
            self.buf = StringIO()
            if value:
                print("[%s:%d] -- -- --> [%s:%d] " % (self.client_host[0], self.client_host[1],
                                                      self.remote_host[0], self.remote_host[1]),
                      file=config.out)
                if six.PY2:
                    print(value.encode('utf8'), file=config.out)
                else:
                    print(value, file=config.out)
                config.out.flush()
        except IOError as e:
            if e.errno == 32:
                # may be pipe closed
                sys.exit(0)
            else:
                print(e, file=sys.stderr)
                sys.exit(-1)
        finally:
            _printer_lock.release()

    def _if_output(self, mime):
        """
        :type mime: httpcap.content_utils.Mime
        """
        if mime is None:
            # unknown
            return self.parse_config.level >= OutputLevel.ALL_BODY
        elif mime.is_text():
            return self.parse_config.level >= OutputLevel.TEXT_BODY
        elif not mime.is_binary():
            return self.parse_config.level >= OutputLevel.ALL_BODY
        else:
            return False

    def _println(self, line=''):
        if isinstance(line, six.binary_type):
            line = line.decode('utf8')
        self.buf.write(line)
        self.buf.write('\n')

    def _println_if(self, level, line):
        if self.parse_config.level >= level:
            self._println(line)

    def _print_body(self, body, compress, mime, charset):
        """
        :type mime: httpcap.content_utils.Mime
        """
        if compress == Compress.GZIP:
            body = content_utils.ungzip(body)
        elif compress == Compress.DEFLATE:
            body = content_utils.decode_deflate(body)

        content = content_utils.decode_body(body, charset)
        if content:
            if mime is None:
                # guess mime...
                if content.startswith('{') and content.endswith('}') or content.startswith('[') \
                        and content.endswith(']'):
                    # just try...
                    mime = Mime(b'application/json')
            if mime is None:
                mime = Mime(b'')
            if self.parse_config.pretty:
                if mime.sub_type == b'json':
                    content_utils.try_print_json(content, self.buf)
                elif mime.sub_type == b"www-form-urlencoded":
                    content_utils.try_decoded_print(content, self.buf)
                else:
                    self.buf.write(content)
            else:
                self.buf.write(content)
            self.buf.write('\n')
