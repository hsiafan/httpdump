package main

import "testing"

func TestParseMimeType(t *testing.T) {
	var mimeType = parseMimeType("application/json")
	if mimeType.Type != "application" {
		t.Fail()
	}
	if mimeType.subType != "json" {
		t.Fail()
	}
	if !mimeType.isTextContent() {
		t.Fail()
	}
	if mimeType.isBinaryContent() {
		t.Fail()
	}
}

func TestParseXMimeType(t *testing.T) {
	var mimeType = parseMimeType("application/x-msdownload")
	if mimeType.Type != "application" {
		t.Fail()
	}
	if mimeType.subType != "msdownload" {
		t.Fail()
	}
	if mimeType.scope != "x" {
		t.Fail()
	}
	if mimeType.isTextContent() {
		t.Fail()
	}
	if !mimeType.isBinaryContent() {
		t.Fail()
	}
}

func TestVndMimeType(t *testing.T) {
	var mimeType = parseMimeType("application/vnd.ms-powerpoint.template.macroenabled.12")
	if mimeType.Type != "application" {
		t.Fail()
	}
	if mimeType.subType != "ms-powerpoint" {
		t.Fail()
	}
	if mimeType.scope != "vnd" {
		t.Fail()
	}
	if mimeType.isTextContent() {
		t.Fail()
	}
	if !mimeType.isBinaryContent() {
		t.Fail()
	}
}