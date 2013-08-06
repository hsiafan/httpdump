#coding=utf-8
__author__ = 'dongliu'

import json
import StringIO
import gzip


def print_json(text, outputfile):

    if text is None:
        return
    if len(text) > 500000:
        # do not process to large text
        return False
    if text.startswith('{') and text.endswith('}') or text.startswith('{') and text.endswith('}'):
        # do not process a non-list-dict json
        try:
            data = json.loads(text)
            outputfile.write(json.dumps(data, indent=2, ensure_ascii=False, separators=(',', ': ')).encode('utf-8'))
            return True
        except Exception as e:
            return False
    else:
        return False


def isgzip(content):
    """
    test if content is gzipped by magic num.
    """
    if content is not None and len(content) > 10 \
        and ord(content[0:1]) == 31 and ord(content[1:2]) == 139 \
        and ord(content[2:3]) == 8:
        return True
    return False


def ungzip(content):
    """ungip content"""
    try:
        compresssteam = StringIO.StringIO(content)
        gzipper = gzip.GzipFile(fileobj=compresssteam)
        content = gzipper.read()
        return content
    except:
        return content


def parse_http_header(header):
    header = header.strip()
    idx = header.find(':')
    if idx < 0:
        return None, None
    else:
        return header[0:idx].strip(), header[idx + 1:].strip()


def ishttprequest(body):
    idx = body.find(' ')
    if idx < 0:
        return False
    method = body[0:idx].lower()
    return method in ('get', 'post', 'put', 'delete')


def ishttpresponse(body):
    return body.startswith('HTTP/') or body.startswith('http/')


def parse_content_type(content_type):
    if not content_type:
        return None, None
    idx = content_type.find(';')
    if idx < 0:
        idx = len(content_type)
    mime = content_type[0:idx]
    encoding = content_type[idx + 1:]
    if len(encoding) > 0:
        eidx = encoding.find('=')
        if eidx > 0:
            encoding = encoding[eidx + 1:]
        else:
            encoding = ''
    return mime.strip().lower(), encoding.strip().lower()


def istextbody(mime):
    if not mime:
        return False
    return 'text' in mime or 'html' in mime or 'xml' in mime or 'json' in mime or 'script' in mime or 'www-form-urlencoded' in mime

def isbinarybody(mime):
    if not mime:
        return False
    # some stupid client set mime to octet-stream even if it is a text content.
    # and we cannot exclude the reponse without content-type headers.
    # TODO: we need to judge if body is text by content.
    return 'image' in mime or 'octet-stream' in mime or 'video' in mime or 'pdf' in mime

def decode_body(content, charset):
    if charset:
        try:
            return content.decode(charset).encode('utf-8')
        except:
            return content
    else:
        # todo: encoding detect
        try:
            return content.decode('utf-8').encode('utf-8')
        except:
            pass
        try:
            return content.decode('gb18030').encode('utf-8')
        except:
            pass
        return content