package main

import (
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestReceiveWindow(t *testing.T) {

	window := newReceiveWindow(4)

	// init insert
	window.insert(&layers.TCP{Seq: 10005, BaseLayer: layers.BaseLayer{Payload: []byte{1, 2}}})
	window.insert(&layers.TCP{Seq: 10000, BaseLayer: layers.BaseLayer{Payload: []byte{7, 8, 9, 0}}})
	window.insert(&layers.TCP{Seq: 10010, BaseLayer: layers.BaseLayer{Payload: []byte{2, 3, 4, 5}}})
	window.insert(&layers.TCP{Seq: 10005, BaseLayer: layers.BaseLayer{Payload: []byte{1, 2}}})
	assert.Equal(t, 3, window.size)
	assert.Equal(t, 0, window.start)
	assert.Equal(t, uint32(10000), window.buffer[0].Seq)
	assert.Equal(t, uint32(10005), window.buffer[1].Seq)
	assert.Equal(t, uint32(10010), window.buffer[2].Seq)

	window.insert(&layers.TCP{Seq: 10009, BaseLayer: layers.BaseLayer{Payload: []byte{7, 8, 9, 0}}})
	assert.Equal(t, uint32(10000), window.buffer[0].Seq)
	assert.Equal(t, uint32(10005), window.buffer[1].Seq)

	// expand
	window.insert(&layers.TCP{Seq: 10030, BaseLayer: layers.BaseLayer{Payload: []byte{7, 8, 9, 0}}})
	assert.Equal(t, 5, window.size)
	assert.Equal(t, 0, window.start)

	c := make(chan *layers.TCP, 1000)
	// confirm
	window.confirm(10020, c)
	assert.Equal(t, 1, window.size)
	assert.Equal(t, 4, window.start)
}
