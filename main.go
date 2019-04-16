package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"runtime"
	"time"

	"strconv"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/hsiafan/vlog"
)

var logger = vlog.CurrentPackageLogger()

func init() {
	logger.SetAppenders(vlog.NewConsole2Appender())
}

var waitGroup sync.WaitGroup
var printerWaitGroup sync.WaitGroup

// Config is user config for http traffics
type Config struct {
	level      string
	filterIP   string
	filterPort uint16
	host       string
	uri        string
	status     int
	force      bool
	pretty     bool
	output     string
}

func listenOneSource(handle *pcap.Handle) chan gopacket.Packet {
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()
	return packets
}

// set packet capture filter, by ip and port
func setDeviceFilter(handle *pcap.Handle, filterIP string, filterPort uint16) error {
	var bpfFilter = "tcp"
	if filterPort != 0 {
		bpfFilter += " port " + strconv.Itoa(int(filterPort))
	}
	if filterIP != "" {
		bpfFilter += " ip host " + filterIP
	}
	return handle.SetBPFFilter(bpfFilter)
}

// adapter multi channels to one channel. used to aggregate multi devices data
func mergeChannel(channels []chan gopacket.Packet) chan gopacket.Packet {
	var channel = make(chan gopacket.Packet)
	for _, ch := range channels {
		go func(c chan gopacket.Packet) {
			for packet := range c {
				channel <- packet
			}
		}(ch)
	}
	return channel
}

func openSingleDevice(device string, filterIP string, filterPort uint16) (localPackets chan gopacket.Packet, err error) {
	defer func() {
		if msg := recover(); msg != nil {
			switch x := msg.(type) {
			case string:
				err = errors.New(x)
			case error:
				err = x
			default:
				err = errors.New("unknown panic")
			}
			localPackets = nil
		}
	}()
	handle, err := pcap.OpenLive(device, 65536, false, pcap.BlockForever)
	if err != nil {
		return
	}

	if err := setDeviceFilter(handle, filterIP, filterPort); err != nil {
		if err != nil {
			logger.Warn("set capture filter failed, ", err)
		}
	}
	localPackets = listenOneSource(handle)
	return
}

func main() {
	var flagSet = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	var level = flagSet.String("level", "header", "Output level, options are: url(only url) | header(http headers) | all(headers, and textuary http body)")
	var filePath = flagSet.String("file", "", "Read from pcap file. If not set, will capture data from network device by default")
	var device = flagSet.String("device", "any", "Capture packet from network device. If is any, capture all interface traffics")
	var filterIP = flagSet.String("ip", "", "Filter by ip, if either source or target ip is matched, the packet will be processed")
	var filterPort = flagSet.Uint("port", 0, "Filter by port, if either source or target port is matched, the packet will be processed.")
	var host = flagSet.String("filter-host", "", "Filter by request host, using wildcard match(*, ?)")
	var uri = flagSet.String("filter-uri", "", "Filter by request url path, using wildcard match(*, ?)")
	var status = flagSet.Int("status", 0, "Filter by response status code")
	var force = flagSet.Bool("force", false, "Force print unknown content-type http body even if it seems not to be text content")
	var pretty = flagSet.Bool("pretty", false, "Try to format and prettify json content")
	var output = flagSet.String("output", "", "Write result to file [output] instead of stdout")
	flagSet.Parse(os.Args[1:])

	if *filterPort < 0 || *filterPort >= 65536 {
		fmt.Fprint(os.Stderr, "ignored invalid port ", *filterPort)
		*filterPort = 0
	}

	var config = &Config{
		level:      *level,
		filterIP:   *filterIP,
		filterPort: uint16(*filterPort),
		host:       *host,
		uri:        *uri,
		status:     *status,
		force:      *force,
		pretty:     *pretty,
		output:     *output,
	}

	var packets chan gopacket.Packet
	if *filePath != "" {
		// read from pcap file
		var handle, err = pcap.OpenOffline(*filePath)
		if err != nil {
			logger.Error("Open file", *filePath, "error:", err)
			return
		}
		packets = listenOneSource(handle)
	} else if *device == "any" && runtime.GOOS != "linux" {
		// capture all device
		// Only linux 2.2+ support any interface. we have to list all network device and listened on them all
		interfaces, err := pcap.FindAllDevs()
		if err != nil {
			logger.Error("find device error:", err)
			return
		}

		var packetsSlice = make([]chan gopacket.Packet, len(interfaces))
		for _, itf := range interfaces {
			localPackets, err := openSingleDevice(itf.Name, config.filterIP, config.filterPort)
			if err != nil {
				logger.Warn("open device", device, "error:", err)
				continue
			}
			packetsSlice = append(packetsSlice, localPackets)
		}
		packets = mergeChannel(packetsSlice)
	} else if *device != "" {
		// capture one device
		var err error
		packets, err = openSingleDevice(*device, config.filterIP, config.filterPort)
		if err != nil {
			logger.Error("listen on device", *device, "failed, error:", err)
			return
		}
	} else {
		fmt.Fprintln(os.Stderr, "no device or pcap file specified.")
		flagSet.Usage()
		return
	}

	var handler = &HTTPConnectionHandler{
		config:  config,
		printer: newPrinter(*output),
	}
	var assembler = newTCPAssembler(handler)
	assembler.filterIP = config.filterIP
	assembler.filterPort = config.filterPort
	var ticker = time.Tick(time.Second * 30)

outer:
	for {
		select {
		case packet := <-packets:
			// A nil packet indicates the end of a pcap file.
			if packet == nil {
				break outer
			}

			// only assembly tcp/ip packets
			if packet.NetworkLayer() == nil || packet.TransportLayer() == nil ||
				packet.TransportLayer().LayerType() != layers.LayerTypeTCP {
				continue
			}
			var tcp = packet.TransportLayer().(*layers.TCP)

			assembler.assemble(packet.NetworkLayer().NetworkFlow(), tcp, packet.Metadata().Timestamp)

		case <-ticker:
			// flush connections that haven't seen activity in the past 2 minutes.
			assembler.flushOlderThan(time.Now().Add(time.Minute * -2))
		}
	}

	assembler.finishAll()
	waitGroup.Wait()
	handler.printer.finish()
	printerWaitGroup.Wait()
}
