package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/smallnest/dropspy"
	"github.com/spf13/pflag"
)

// filter struct is used to store filter conditions
type filter struct {
	ifaces     map[uint32]bool  // Mapping of interface indices
	min, max   uint             // Minimum and maximum packet length
	xSym, iSym []*regexp.Regexp // Exclude and include symbol regex
	bpf        *pcap.BPF        // BPF filter
}

// Match method is used to check if a packet matches the filter conditions
func (f *filter) Match(pa *dropspy.PacketAlert) bool {
	if len(f.ifaces) > 0 {
		if !f.ifaces[pa.Link()] { // Check if the packet is from the specified interface
			return false
		}
	}

	plen := uint(pa.Length()) // Get packet length

	if f.min != 0 && plen < f.min { // Check minimum length
		return false
	}

	if f.max != 0 && plen > f.max { // Check maximum length
		return false
	}

	sym := pa.Symbol() // Get packet symbol

	if len(f.xSym) != 0 {
		for _, rx := range f.xSym {
			if rx.MatchString(sym) { // Check if it matches the exclude symbol
				return false
			}
		}
	}

	if len(f.iSym) != 0 {
		for _, rx := range f.iSym {
			if !rx.MatchString(sym) { // Check if it matches the include symbol
				return false
			}
		}
	}

	if f.bpf != nil {
		packet := pa.Packet() // Get raw packet

		ci := gopacket.CaptureInfo{
			CaptureLength: len(packet), // Capture length
			Length:        int(plen),   // Packet length
		}

		if !f.bpf.Matches(ci, packet) { // Check BPF filter
			return false
		}
	}

	return true // Return true if all conditions match
}

var (
	packetModeTruncation int = 100 // Packet mode truncation length
)

func main() {
	var (
		printHex bool     // Whether to print hex data
		ifaces   []string // Interface parameters
		xsyms    []string // Exclude symbol parameters
		isyms    []string // Include symbol parameters
		maxDrops uint64   // Maximum drop count
		timeout  string   // Capture timeout
		hw, sw   bool     // Hardware and software drop flags

		filter filter // Filter instance

		summary bool // Summary flag

		err error // Error variable
	)

	// Define command line flags
	pflag.StringArrayVarP(&ifaces, "iface", "I", nil, "show only drops on this interface (may be repeated)") // Show only drops on specified interface
	pflag.StringArrayVar(&xsyms, "xsym", nil, "exclude drops from syms matching regexp (may be repeated)")   // Exclude symbols matching regex
	pflag.StringArrayVar(&isyms, "isym", nil, "include drops from syms matching regexp (may be repeated)")   // Include symbols matching regex
	pflag.UintVar(&filter.min, "minlen", 0, "minimum packet length for drops")                               // Set minimum packet length
	pflag.UintVar(&filter.max, "maxlen", 0, "maximum packet length for drops")                               // Set maximum packet length
	pflag.Uint64VarP(&maxDrops, "count", "c", 0, "maximum drops to record")                                  // Set maximum drop count
	pflag.StringVarP(&timeout, "timeout", "w", "", "duration to capture for (300ms, 2h15m, &c)")             // Set capture timeout
	pflag.BoolVar(&hw, "hw", true, "record hardware drops")                                                  // Record hardware drops
	pflag.BoolVar(&sw, "sw", true, "record software drops")                                                  // Record software drops
	pflag.BoolVar(&printHex, "hex", false, "print hex dumps of matching packets")                            // Print hex dumps of matching packets
	pflag.BoolVar(&summary, "summary", false, "print summary of drops")                                      // Print summary of drops
	// pflag.BoolP("help", "h", false, "")

	// Set usage instructions
	pflag.Usage = func() {
		fmt.Fprintf(os.Stderr, "%s: Report packet drops from Linux kernel DM_MON.\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "%s [flags] [pcap filter]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "ie: %s --hex -I eth0 udp port 53\n", os.Args[0])
		pflag.PrintDefaults() // Print default values of all flags
	}

	pflag.ErrHelp = fmt.Errorf("")
	pflag.Parse() // Parse command line flags

	pcapExpr := strings.Join(pflag.Args(), " ") // Get pcap filter expression
	if pcapExpr != "" {
		filter.bpf, err = pcap.NewBPF(layers.LinkTypeEthernet, packetModeTruncation, pcapExpr) // Create BPF filter
		if err != nil {
			fmt.Fprintf(os.Stderr, "pcap expression: %s\n", err) // Print error message
			os.Exit(1)                                           // Exit program
		}
	}

	if len([]string(xsyms)) > 0 && len([]string(isyms)) > 0 {
		fmt.Fprintf(os.Stderr, "-xsym and -isym are mutually exclusive\n") // Exclude and include symbols cannot be used together
		os.Exit(1)                                                         // Exit program
	}

	// Compile exclude symbol regex
	for _, symexpr := range []string(xsyms) {
		rx, err := regexp.Compile(symexpr) // Compile regex
		if err != nil {
			fmt.Fprintf(os.Stderr, "regexp compile %s: %s\n", symexpr, err) // Print error message
			os.Exit(1)                                                      // Exit program
		}

		filter.xSym = append(filter.xSym, rx) // Add to filter
	}

	// Compile include symbol regex
	for _, symexpr := range []string(isyms) {
		rx, err := regexp.Compile(symexpr) // Compile regex
		if err != nil {
			fmt.Fprintf(os.Stderr, "regexp compile %s: %s\n", symexpr, err) // Print error message
			os.Exit(1)                                                      // Exit program
		}

		filter.iSym = append(filter.iSym, rx) // Add to filter
	}

	links, err := dropspy.LinkList() // Get network interface list
	if err != nil {
		fmt.Fprintf(os.Stderr, "retrieve links: %s\n", err) // Print error message
		os.Exit(1)                                          // Exit program
	}

	filter.ifaces = map[uint32]bool{} // Initialize interface mapping

	// Handle specified interfaces
	for _, iface := range []string(ifaces) {
		var rx *regexp.Regexp

		if strings.HasPrefix(iface, "/") && strings.HasSuffix(iface, "/") {
			rx, err = regexp.Compile(iface[1 : len(iface)-2]) // Compile regex
			if err != nil {
				fmt.Fprintf(os.Stderr, "compile interface regexp for %s: %s\n", iface[1:len(iface)-2], err) // Print error message
				os.Exit(1)                                                                                  // Exit program
			}
		} else {
			rx, err = regexp.Compile("^" + iface + "$") // Compile exact match regex
			if err != nil {
				fmt.Fprintf(os.Stderr, "compile interface regexp for %s: %s\n", iface, err) // Print error message
				os.Exit(1)                                                                  // Exit program
			}
		}

		found := false
		for k, v := range links {
			if v == iface {
				if rx.MatchString(v) { // Check if it matches
					filter.ifaces[k] = true // Add interface to filter
					found = true
					break
				}
			}
		}

		if !found {
			fmt.Fprintf(os.Stderr, "no such interface '%s'\n", iface) // Print error message
			os.Exit(1)                                                // Exit program
		}
	}

	session, err := dropspy.NewSession(links) // Create new dropspy session
	if err != nil {
		fmt.Fprintf(os.Stderr, "connect to drop_mon: %s\n", err) // Print error message
		os.Exit(1)                                               // Exit program
	}

	sigCh := make(chan os.Signal, 1)                                       // Create signal channel
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT) // Listen for interrupt signal
	go func() {
		_ = <-sigCh                                                  // Wait for signal
		fmt.Fprintf(os.Stderr, "got C-c: cleaning up and exiting\n") // Print cleanup message
		session.Stop(true, true)                                     // Stop session
		os.Exit(1)                                                   // Exit program
	}()

	defer func() {
		session.Stop(true, true) // Ensure session stops on exit
	}()

	err = session.Start(sw, hw) // Start session
	if err != nil {
		fmt.Fprintf(os.Stderr, "enable drop_mon alerts: %s\n", err) // Print error message
		os.Exit(1)                                                  // Exit program
	}

	var deadline time.Time // Define deadline

	if timeout != "" {
		dur, err := time.ParseDuration(timeout) // Parse timeout
		if err != nil {
			fmt.Fprintf(os.Stderr, "can't parse timeout: %s\n", err) // Print error message
			os.Exit(1)                                               // Exit program
		}

		deadline = time.Now().Add(dur) // Set deadline
	}

	dropCount := uint64(0) // Initialize drop count

	var summaries = make(map[string]int)

	defer func() {
		if summary {
			for k, v := range summaries {
				fmt.Printf("%s: %d\n", k, v)
			}
		}
	}()

	start := time.Now()
	for {
		err = session.ReadUntil(deadline, func(pa dropspy.PacketAlert) bool {
			if filter.Match(&pa) { // Check if packet matches filter conditions
				dropCount += 1 // Increment drop count

				if summary {
					key := fmt.Sprintf("%s (%016x) [%s] [%s]", pa.Symbol(), pa.PC(), dropspy.GetOrigin(&pa), dropspy.GetDropReason(&pa))
					summaries[key] += 1

					now := time.Now()
					if now.Sub(start) > time.Second {
						start = now
						for k, v := range summaries {
							if strings.HasSuffix(k, " []") {
								k = k[:len(k)-3]
							}
							fmt.Printf("%d drops at %s\n", v, k)
						}
						summaries = make(map[string]int)
					}
				} else {
					// Record drop information
					pa.Output(links)
					if printHex {
						fmt.Println(hex.Dump(pa.L3Packet())) // Print hex data
					}
					log.Println("----------------") // Separator
				}

				if maxDrops != 0 && dropCount == maxDrops { // Check if maximum drop count is reached
					fmt.Fprintf(os.Stderr, "maximum drops reached, exiting\n") // Print message
					return false                                               // Stop reading
				}
			}

			return true // Continue reading
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "read: %s\n", err) // Print error message
			time.Sleep(250 * time.Millisecond)        // Pause for a while
		} else {
			return // Exit loop
		}
	}
}
