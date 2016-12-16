package main

import (
	"testing"
	"github.com/google/gopacket/layers"
)

func TestReceiveWindow(t *testing.T) {

	window := newReceiveWindow(4)

	// init insert
	window.insert(&layers.TCP{Seq:10005, BaseLayer:layers.BaseLayer{Payload:[]byte{1, 2}}})
	window.insert(&layers.TCP{Seq:10000, BaseLayer:layers.BaseLayer{Payload:[]byte{7, 8, 9, 0}}})
	window.insert(&layers.TCP{Seq:10010, BaseLayer:layers.BaseLayer{Payload:[]byte{2, 3, 4, 5}}})
	window.insert(&layers.TCP{Seq:10005, BaseLayer:layers.BaseLayer{Payload:[]byte{1, 2}}})
	if window.size != 3 {
		t.Fatal("window size should be 3")
	}
	if window.start != 0 {
		t.Fatal("window start should be 0")
	}
	if window.buffer[0].Seq != 10000 {
		t.FailNow()
	}
	if window.buffer[1].Seq != 10005 {
		t.FailNow()
	}
	if window.buffer[2].Seq != 10010 {
		t.Fatal("window.buffer[2].Seq should be 10010")
	}

	window.insert(&layers.TCP{Seq:10009, BaseLayer:layers.BaseLayer{Payload:[]byte{7, 8, 9, 0}}})
	if window.buffer[0].Seq != 10000 {
		t.FailNow()
	}
	if window.buffer[1].Seq != 10005 {
		t.FailNow()
	}

	// expand
	window.insert(&layers.TCP{Seq:10030, BaseLayer:layers.BaseLayer{Payload:[]byte{7, 8, 9, 0}}})
	if window.size != 5 {
		t.Fatal("window size should be 5")
	}
	if window.start != 0 {
		t.Fatal("window start should be 0")
	}

	c := make(chan *layers.TCP, 1000)
	// confirm
	window.confirm(10020, c)
	if window.size != 1 {
		t.Fatal("window size should be 1, but:", window.size)
	}
	if window.start != 4 {
		t.Fatal("window start should be 4, but:", window.start)
	}
}
