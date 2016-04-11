package main

import (
	"strings"
)

type mimeType struct {
	Type    string
	subType string
	scope   string
}

func parseMimeType(contentTypeStr string) mimeType {
	var idx = strings.Index(contentTypeStr, "/")
	if idx == -1 {
		// should not happen
		return mimeType{contentTypeStr, "", ""}
	} else {
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
}

//TODO: multipart/form-data

var textTypes = map[string]bool{"text":true}
var textSubTypes = map[string]bool{"html":true, "xml":true, "json":true, "www-form-urlencoded":true,
	"javascript":true, "postscript":true, "atomcat+xml":true, "atomsvc+xml":true, "atom+xml":true,
	"xml-dtd":true, "ecmascript":true, "java-jnlp-file":true, "latex":true, "mpegurl":true, "rdf+xml":true,
	"rtf":true, "rss+xml":true, "svg+xml":true, "uri-list":true, "wsdl+xml":true, "xhtml+xml":true, "xslt+xml":true,
}

func (ct mimeType) isTextContent() bool {
	return textTypes[ct.Type] || textSubTypes[ct.subType]
}

var binaryTypes = map[string]bool{"image":true, "audio":true, "video":true}
var binarySubtypes = map[string]bool{"7z-compressed":true, "abiword":true, "ace-compressed":true,
	"shockwave-flash":true, "pdf":true, "director":true, "bzip":true, "bzip2":true, "debian-package":true,
	"epub+zip":true, "font-ghostscript":true, "font-bdf":true, "java-archive":true, "java-vm":true,
	"java-serialized-object":true, "msaccess":true, "msdownload":true, "ms-application":true, "ms-fontobject":true,
	"ms-excel":true, "openxmlformats-officedocument":true, "msbinder":true, "ms-officetheme":true, "onenote":true,
	"ms-powerpoint":true, "ms-project":true, "mspublisher":true, "msschedule":true, "silverlight-app":true, "visio":true,
	"ms-wmd":true, "ms-htmlhelp":true, "msword":true, "ms-works":true, "oda":true, "ogg":true, "oasis":true, "sun":true,
	"font-otf":true, "x-font-ttf":true, "unity":true, "zip":true, "x509-ca-cert":true, "octet-stream":true,
	"png":true, "ppt":true, "xls":true,
}

func (ct mimeType)  isBinaryContent() bool {
	return binaryTypes[ct.Type] || binarySubtypes[ct.subType]
}