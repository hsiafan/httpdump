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
)

var waitGroup sync.WaitGroup
var printerWaitGroup sync.WaitGroup

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
		fmt.Fprintln(os.Stderr, "set capture filter failed, ", err)
	}
	localPackets = listenOneSource(handle)
	return
}

// Command line options
type Option struct {
	Level     string        `default:"header" description:"Output level, options are: url(only url) | header(http headers) | all(headers, and textuary http body)"`
	File      string        `description:"Read from pcap file. If not set, will capture data from network device by default"`
	Device    string        `default:"any" description:"Capture packet from network device. If is any, capture all interface traffics"`
	Ip        string        `description:"Filter by ip, if either source or target ip is matched, the packet will be processed"`
	Port      uint          `description:"Filter by port, if either source or target port is matched, the packet will be processed."`
	Host      string        `description:"Filter by request host, using wildcard match(*, ?)"`
	Uri       string        `description:"Filter by request url path, using wildcard match(*, ?)"`
	Status    string        `description:"Filter by response status code. Can use range. eg: 200, 200-300 or 200:300-400"`
	StatusSet *IntSet       `ignore:"true"`
	Force     bool          `description:"Force print unknown content-type http body even if it seems not to be text content"`
	Pretty    bool          `description:"Try to format and prettify json content"`
	Curl      bool          `description:"Output an equivalent curl command for each http request"`
	DumpBody  bool          `description:"dump http request/response body to file"`
	Output    string        `description:"Write result to file [output] instead of stdout"`
	Idle      time.Duration `default:"4m" description:"Idle time to remove connection if no package received"`
}

func main() {

	var o = &Option{}
	flag.StringVar(&o.Level, "level", "header", "Output level, options are: url(only url) | header(http headers) | all(headers, and textuary http body)")
	flag.StringVar(&o.File, "file", "", "Read from pcap file. If not set, will capture data from network device by default")
	flag.StringVar(&o.Device, "device", "any", "Capture packet from network device. If is any, capture all interface traffics")
	flag.StringVar(&o.Ip, "ip", "", "Filter by ip, if either source or target ip is matched, the packet will be processed")
	flag.UintVar(&o.Port, "port", 0, "Filter by port, if either source or target port is matched, the packet will be processed")
	flag.StringVar(&o.Host, "host", "", "Filter by request host, using wildcard match(*, ?)")
	flag.StringVar(&o.Uri, "uri", "", "Filter by request url path, using wildcard match(*, ?)")
	flag.StringVar(&o.Status, "status", "", "Filter by response status code. Can use range. eg: 200, 200-300 or 200:300-400")
	flag.BoolVar(&o.Force, "force", false, "Force print unknown content-type http body even if it seems not to be text content")
	flag.BoolVar(&o.Pretty, "pretty", false, "Try to format and prettify json content")
	flag.BoolVar(&o.Curl, "curl", false, "Output an equivalent curl command for each http request")
	flag.BoolVar(&o.DumpBody, "dump-body", false, "dump http request/response body to file")
	flag.StringVar(&o.Output, "output", "", "Write result to file instead of stdout")
	flag.DurationVar(&o.Idle, "idle", time.Minute*4, "Idle time to remove connection if no package received")
	flag.Parse()

	err := run(o)
	if err != nil {
		fmt.Println(err)
		return
	}
}

func run(option *Option) error {
	if option.Port > 65536 {
		return fmt.Errorf("ignored invalid port %v", option.Port)
	}

	if option.Status != "" {
		statusSet, err := ParseIntSet(option.Status)
		if err != nil {
			return fmt.Errorf("status range not valid %v", option.Status)
		}
		option.StatusSet = statusSet
	}

	var packets chan gopacket.Packet
	if option.File != "" {
		//TODO: read file stdin
		// read from pcap file
		var handle, err = pcap.OpenOffline(option.File)
		if err != nil {
			return fmt.Errorf("open file %v error: %w", option.File, err)
		}
		packets = listenOneSource(handle)
	} else if option.Device == "any" && runtime.GOOS != "linux" {
		// capture all device
		// Only linux 2.2+ support any interface. we have to list all network device and listened on them all
		interfaces, err := pcap.FindAllDevs()
		if err != nil {
			return fmt.Errorf("find device error: %w", err)
		}

		var packetsSlice = make([]chan gopacket.Packet, len(interfaces))
		for _, itf := range interfaces {
			localPackets, err := openSingleDevice(itf.Name, option.Ip, uint16(option.Port))
			if err != nil {
				fmt.Fprintln(os.Stderr, "open device", itf, "error:", err)
				continue
			}
			packetsSlice = append(packetsSlice, localPackets)
		}
		packets = mergeChannel(packetsSlice)
	} else if option.Device != "" {
		// capture one device
		var err error
		packets, err = openSingleDevice(option.Device, option.Ip, uint16(option.Port))
		if err != nil {
			return fmt.Errorf("listen on device %v failed, error: %w", option.Device, err)
		}
	} else {
		return errors.New("no device or pcap file specified")
	}

	var handler = &HTTPConnectionHandler{
		option: option,
		// TODO: stdout
		printer: newPrinter(option.Output),
	}
	var assembler = newTCPAssembler(handler)
	assembler.filterIP = option.Ip
	assembler.filterPort = uint16(option.Port)
	var ticker = time.Tick(time.Second * 10)

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
			// flush connections that haven't been activity in the idle time
			assembler.flushOlderThan(time.Now().Add(-option.Idle))
		}
	}

	assembler.finishAll()
	waitGroup.Wait()
	handler.printer.finish()
	printerWaitGroup.Wait()
	return nil
}
