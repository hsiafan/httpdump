from __future__ import unicode_literals, print_function, division

import zlib
import six
from six.moves.urllib.parse import quote, unquote
from httpcap.constant import Compress

import json
from io import BytesIO
import gzip


class Mime(object):
    _text_types = {b"text"}
    _text_sub_types = {
        b"html", b"xml", b"json", b"www-form-urlencoded",
        b"javascript", b"postscript", b"atomcat+xml", b"atomsvc+xml", b"atom+xml",
        b"xml-dtd", b"ecmascript", b"java-jnlp-file", b"latex", b"mpegurl", b"rdf+xml",
        b"rtf", b"rss+xml", b"svg+xml", b"uri-list", b"wsdl+xml", b"xhtml+xml", b"xslt+xml",
        b"ns-proxy-autoconfig", b"javascript-config",
    }
    _binary_types = {b"image", b"audio", b"video"}
    _binary_sub_types = {
        b"7z-compressed", b"abiword", b"ace-compressed",
        b"shockwave-flash", b"pdf", b"director", b"bzip", b"bzip2", b"debian-package",
        b"epub+zip", b"font-ghostscript", b"font-bdf", b"java-archive", b"java-vm",
        b"java-serialized-object", b"msaccess", b"msdownload", b"ms-application", b"ms-fontobject",
        b"ms-excel", b"openxmlformats-officedocument", b"msbinder", b"ms-officetheme", b"onenote",
        b"ms-powerpoint", b"ms-project", b"mspublisher", b"msschedule", b"silverlight-app", b"visio",
        b"ms-wmd", b"ms-htmlhelp", b"msword", b"ms-works", b"oda", b"ogg", b"oasis", b"sun",
        b"font-otf", b"x-font-ttf", b"unity", b"zip", b"x509-ca-cert", b"octet-stream",
        b"png", b"ppt", b"xls",
    }

    def __init__(self, mime_str):
        idx = mime_str.find(b'/')
        if idx < 0:
            self.main_type = mime_str
            self.sub_type = b''
        else:
            self.main_type = mime_str[:idx]
            sub_type = mime_str[idx + 1:]
            if sub_type.startswith(b'x-'):
                sub_type = sub_type[2:]
            if sub_type.startswith(b'vnd.'):
                sub_type = sub_type[4:]
            idx2 = sub_type.find(b'.')
            if idx2 > 0:
                sub_type = sub_type[:idx2]
            self.sub_type = sub_type

    # if is text type mime
    def is_text(self):
        return self.main_type in Mime._text_types or self.sub_type in Mime._text_sub_types

    # if is binary type mime
    def is_binary(self):
        return self.main_type in Mime._binary_sub_types or self.sub_type in Mime._binary_sub_types


def try_print_json(text, output_file):
    if text is None:
        return
    # may be json
    try:
        data = json.loads(text)
        output_file.write(
            json.dumps(data, indent=2, ensure_ascii=False, separators=(',', ': ')))
        return True
    except Exception:
        output_file.write(text)
        return False


def try_decoded_print(content, buf):
    content = unquote(content)
    buf.write(content)


def get_compress_type(content_encoding):
    content_encoding = content_encoding.strip()
    if content_encoding == b'gzip':
        return Compress.GZIP
    elif content_encoding == b'deflate':
        return Compress.DEFLATE
    else:
        # there are others compress token, just process the most common two now.
        return Compress.IDENTITY


def gzipped(content):
    """
    test if content is gzipped by magic num.
    first two bytes of gzip stream should be 0x1F and 0x8B,
    the third byte represent for compress algorithm, always 8(deflate) now
    """
    if content is not None and len(content) > 10 \
            and ord(content[0:1]) == 31 and ord(content[1:2]) == 139 \
            and ord(content[2:3]) == 8:
        return True
    return False


def ungzip(content):
    """ungzip content"""
    try:
        buf = BytesIO(content)
        gzip_file = gzip.GzipFile(fileobj=buf)
        content = gzip_file.read()
        return content
    except:
        import traceback

        traceback.print_exc()
        return content


def decode_deflate(content):
    """decode deflate stream"""
    return zlib.decompressobj(-zlib.MAX_WBITS).decompress(content)


def parse_http_header(header):
    header = header.strip()
    idx = header.find(b':')
    if idx < 0:
        return None, None
    else:
        return header[0:idx].strip(), header[idx + 1:].strip()


_methods = {b'GET', b'POST', b'PUT', b'DELETE', b'HEAD', b'TRACE', b'OPTIONS', b'PATCH'}


def is_request(body):
    """judge if is http request by the first line"""
    idx = body.find(b' ')
    if idx < 0:
        return False
    method = body[0:idx]
    return method in _methods


def is_response(body):
    """judge if is http response by http status line"""
    return body.startswith(b'HTTP/')


def parse_content_type(content_type):
    """parse content-type header, return mime and charset"""
    if not content_type:
        return None, None
    idx = content_type.find(b';')
    if idx < 0:
        idx = len(content_type)
    mime = content_type[0:idx].strip().lower()
    encoding = content_type[idx + 1:]
    if len(encoding) > 0:
        eidx = encoding.find(b'=')
        if eidx > 0 and encoding[0:eidx].strip() == b'charset':
            encoding = encoding[eidx + 1:]
        else:
            encoding = b''
    return Mime(mime), encoding.strip().lower()


def decode_body(content, charset):
    if content is None:
        return None
    if content == b'':
        return ''
    if charset:
        if isinstance(charset, six.binary_type):
            charset = charset.decode('utf8')
        try:
            return content.decode(charset)
        except UnicodeDecodeError:
            return '{{decode content failed with charset: {}}}'.format(charset)

    # todo: encoding detect
    try:
        return content.decode('utf-8')
    except UnicodeDecodeError:
        pass
    try:
        return content.decode('gb18030')
    except  UnicodeDecodeError:
        pass
    return '{decode content failed, unknown charset}'
