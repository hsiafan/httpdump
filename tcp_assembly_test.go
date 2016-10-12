package main

import (
	"testing"
	"github.com/google/gopacket/layers"
)

func TestReceiveWindow(t *testing.T) {

	window := newReceiveWindow(4)

	// init insert
	window.insert(&layers.TCP{Seq:10005})
	window.insert(&layers.TCP{Seq:10000})
	window.insert(&layers.TCP{Seq:10010})
	window.insert(&layers.TCP{Seq:10005})
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

	window.insert(&layers.TCP{Seq:10009})
	if window.buffer[0].Seq != 10000 {
		t.FailNow()
	}
	if window.buffer[1].Seq != 10005 {
		t.FailNow()
	}


	// expand
	window.insert(&layers.TCP{Seq:10030})
	if window.size != 5 {
		t.Fatal("window size should be 5")
	}
	if window.start != 0 {
		t.Fatal("window start should be 0")
	}

	c := make(chan []byte, 1000)
	// confirm
	window.confirm(10020, c)
	if window.size != 1 {
		t.Fatal("window size should be 1, but:", window.size)
	}
	if window.start != 4 {
		t.Fatal("window start should be 4, but:", window.start)
	}


	// rolling insert
	window.insert(&layers.TCP{Seq:10005})
	window.insert(&layers.TCP{Seq:10000})
	window.insert(&layers.TCP{Seq:10010})
	window.insert(&layers.TCP{Seq:10040})
	if window.size != 5 {
		t.Fatal("window size should be 5, but:", window.size)
	}
	if window.start != 4 {
		t.Fatal("window start should be 4, but:", window.start)
	}
	if window.buffer[4].Seq != 10000 {
		t.Fatal("window.buffer[4].Seq should be 10000")
	}
	if window.buffer[0].Seq != 10040 {
		t.Fatal("window.buffer[0].Seq should be 10040")
	}

	// expand
	window.insert(&layers.TCP{Seq:10045})
	window.insert(&layers.TCP{Seq:10050})
	window.insert(&layers.TCP{Seq:10060})
	window.insert(&layers.TCP{Seq:10070})
	if window.size != 9 {
		t.Fatal("window size should be 9, but:", window.size)
	}
	if window.start != 0 {
		t.Fatal("window start should be 0, but:", window.start)
	}
	if window.buffer[8].Seq != 10070 {
		t.Fatal("window.buffer[8].Seq should be 10070")
	}
	if window.buffer[0].Seq != 10000 {
		t.Fatal("window.buffer[0].Seq should be 10000")
	}
	for idx := 0; idx < window.size; idx++ {
		item := window.buffer[(idx + window.start) % len(window.buffer)]
		if item == nil {
			t.Fatalf("window.buffer[%v] is nil", idx)
		}
	}
}