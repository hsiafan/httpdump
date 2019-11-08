package main

import (
	"io"
	"os"
)

// Printer output parsed http messages
type Printer struct {
	outputQueue chan string
	outputFile  io.WriteCloser
}

var maxOutputQueueLen = 4096

func newPrinter(outputPath string) *Printer {
	var outputFile io.WriteCloser
	if outputPath == "" {
		outputFile = os.Stdout
	} else {
		var err error
		outputFile, err = os.OpenFile(outputPath, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0666)
		if err != nil {
			panic(err)
		}

	}
	printer := &Printer{outputQueue: make(chan string, maxOutputQueueLen), outputFile: outputFile}
	printer.start()
	return printer
}

func (printer *Printer) send(msg string) {
	if len(printer.outputQueue) == maxOutputQueueLen {
		// skip this msg
		logger.Warn("too many messages to output, discard current!")
		return
	}
	printer.outputQueue <- msg
}

func (printer *Printer) start() {
	printerWaitGroup.Add(1)
	go printer.printBackground()
}

func (printer *Printer) printBackground() {
	defer printerWaitGroup.Done()
	defer printer.outputFile.Close()
	for msg := range printer.outputQueue {
		_, _ = printer.outputFile.Write([]byte(msg))
	}
}

func (printer *Printer) finish() {
	close(printer.outputQueue)
}
