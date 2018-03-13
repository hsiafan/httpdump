package main

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestParseMimeType(t *testing.T) {
	var mimeType = parseMimeType("application/json")
	assert.Equal(t, "application", mimeType.Type)
	assert.Equal(t, "json", mimeType.subType)
	assert.Equal(t, "", mimeType.scope)
	assert.True(t, mimeType.isTextContent())
	assert.False(t, mimeType.isBinaryContent())
}

func TestParseXMimeType(t *testing.T) {
	var mimeType = parseMimeType("application/x-msdownload")
	assert.Equal(t, "application", mimeType.Type)
	assert.Equal(t, "msdownload", mimeType.subType)
	assert.Equal(t, "x", mimeType.scope)
	assert.False(t, mimeType.isTextContent())
	assert.True(t, mimeType.isBinaryContent())
}

func TestVndMimeType(t *testing.T) {
	var mimeType = parseMimeType("application/vnd.ms-powerpoint.template.macroenabled.12")
	assert.Equal(t, "application", mimeType.Type)
	assert.Equal(t, "ms-powerpoint", mimeType.subType)
	assert.Equal(t, "vnd", mimeType.scope)
	assert.False(t, mimeType.isTextContent())
	assert.True(t, mimeType.isBinaryContent())
}

func TestWildcardMatch(t *testing.T) {
	assert.True(t, wildcardMatch("test", "test"))
	assert.True(t, wildcardMatch("test", "tes*"))
	assert.True(t, wildcardMatch("test", "tes?"))
	assert.True(t, wildcardMatch("test", "t*"))
	assert.True(t, wildcardMatch("test", "*t*"))
	assert.False(t, wildcardMatch("test", "tt*"))
	assert.False(t, wildcardMatch("test", "es"))
}
