package main

import (
	"bytes"
	"io"
	"io/ioutil"
	"strings"

	//"github.com/saintfish/chardet" // not work, realy stupid...
	"golang.org/x/text/encoding"
	"golang.org/x/text/encoding/htmlindex"
	"golang.org/x/text/transform"
)

// mime type struct
type mimeType struct {
	Type    string
	subType string
	scope   string
}

// parse mime type
func parseMimeType(contentTypeStr string) mimeType {
	var idx = strings.Index(contentTypeStr, "/")
	if idx == -1 {
		// should not happen
		return mimeType{contentTypeStr, "", ""}
	}
	var scope = ""
	var subType = contentTypeStr[idx + 1:]
	if strings.HasPrefix(subType, "x-") {
		subType = subType[2:]
		scope = "x"
	} else if strings.HasPrefix(subType, "vnd.") {
		subType = subType[4:]
		scope = "vnd"
	}
	var i = strings.Index(subType, ".")
	if i > 0 {
		subType = subType[:i]
	}
	return mimeType{contentTypeStr[:idx], subType, scope}
}

//TODO: multipart/form-data

var textTypes = map[string]bool{"text": true}
var textSubTypes = map[string]bool{"html": true, "xml": true, "json": true, "www-form-urlencoded": true,
	"javascript": true, "postscript": true, "atomcat+xml": true, "atomsvc+xml": true, "atom+xml": true,
	"xml-dtd": true, "ecmascript": true, "java-jnlp-file": true, "latex": true, "mpegurl": true, "rdf+xml": true,
	"rtf": true, "rss+xml": true, "svg+xml": true, "uri-list": true, "wsdl+xml": true, "xhtml+xml": true, "xslt+xml": true,
	"ns-proxy-autoconfig": true, "javascript-config": true,
}

// if is text type mime
func (ct mimeType) isTextContent() bool {
	return textTypes[ct.Type] || textSubTypes[ct.subType]
}

var binaryTypes = map[string]bool{"image": true, "audio": true, "video": true}
var binarySubtypes = map[string]bool{"7z-compressed": true, "abiword": true, "ace-compressed": true,
	"shockwave-flash": true, "pdf": true, "director": true, "bzip": true, "bzip2": true, "debian-package": true,
	"epub+zip": true, "font-ghostscript": true, "font-bdf": true, "java-archive": true, "java-vm": true,
	"java-serialized-object": true, "msaccess": true, "msdownload": true, "ms-application": true, "ms-fontobject": true,
	"ms-excel": true, "openxmlformats-officedocument": true, "msbinder": true, "ms-officetheme": true, "onenote": true,
	"ms-powerpoint": true, "ms-project": true, "mspublisher": true, "msschedule": true, "silverlight-app": true, "visio": true,
	"ms-wmd": true, "ms-htmlhelp": true, "msword": true, "ms-works": true, "oda": true, "ogg": true, "oasis": true, "sun": true,
	"font-otf": true, "x-font-ttf": true, "unity": true, "zip": true, "x509-ca-cert": true, "octet-stream": true,
	"png": true, "ppt": true, "xls": true,
}

// if is binary type mime
func (ct mimeType) isBinaryContent() bool {
	return binaryTypes[ct.Type] || binarySubtypes[ct.subType]
}

// read reader content to string, using charset specified
func readToStringWithCharset(reader io.Reader, charset string) (string, error) {
	charset = strings.ToUpper(charset)
	var data []byte
	var err error
	if charset == "UTF-8" || charset == "UTF8" {
		data, err = ioutil.ReadAll(reader)
	} else {
		if charset == "GBK" || charset == "GB2312" {
			charset = "GB18030"
		}
		var encoder encoding.Encoding
		encoder, err = htmlindex.Get(charset)
		if err != nil {
			return "", err
		}
		data, err = ioutil.ReadAll(transform.NewReader(reader, encoder.NewDecoder()))
	}
	if err != nil {
		return "", err
	}
	return string(data), err
}

// convert byte array to string, using charset specified
func byteToStringWithCharset(data []byte, charset string) (string, error) {
	charset = strings.ToUpper(charset)
	if charset == "UTF-8" || charset == "UTF8" {
		return string(data), nil
	}
	var reader = bytes.NewBuffer(data)
	return readToStringWithCharset(reader, charset)
}

// parse content type to mimeType and charset
func parseContentType(contentType string) (string, string) {
	var mimeTypeStr, charset string
	idx := strings.Index(contentType, ";")
	if idx < 0 {
		mimeTypeStr = strings.TrimSpace(contentType)
		charset = ""
	} else {
		mimeTypeStr = strings.TrimSpace(contentType[:idx])
		charsetSeg := strings.TrimSpace(contentType[idx + 1:])
		eidx := strings.Index(charsetSeg, "=")
		if eidx < 0 {
			charset = ""
		} else {
			charset = strings.TrimSpace(charsetSeg[eidx + 1:])
		}
	}
	return mimeTypeStr, charset
}

// if sting 'looks like' a json string
func likeJSON(value string) bool {
	if len(value) < 2 {
		return false
	}
	value = strings.TrimSpace(value)
	if value[0] == '[' && value[len(value) - 1] == ']' || value[0] == '{' && value[len(value) - 1] == '}' {
		return true
	}
	return false
}

func isHttpRequestStart(data []byte) bool {
	// guard
	if len(data) < 10 {
		return false
	}

	idx := bytes.IndexByte(data, ' ')
	if idx < 0 || idx > 10 {
		return false
	}
	return bytes.Equal(data, []byte("GET")) || bytes.Equal(data, []byte("POST")) ||
			bytes.Equal(data, []byte("PUT")) || bytes.Equal(data, []byte("HEAD")) ||
			bytes.Equal(data, []byte("DELETE")) || bytes.Equal(data, []byte("PATCH")) || bytes.Equal(data, []byte("TRACE")) ||
			bytes.Equal(data, []byte("OPTIONS"))
}