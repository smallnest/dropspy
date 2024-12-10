package dropspy

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/mdlayher/genetlink"
	"github.com/mdlayher/netlink"
)

// These constants are extracted from the 5.6 mainline
// include/uapi/linux/net_dropmon.h

const (
	CMD_UNSPEC = iota
	CMD_ALERT  // 1
	CMD_CONFIG
	CMD_START
	CMD_STOP
	CMD_PACKET_ALERT // 5
	CMD_CONFIG_GET
	CMD_CONFIG_NEW
	CMD_STATS_GET
	CMD_STATS_NEW
)

const (
	ATTR_UNSPEC     = iota
	ATTR_ALERT_MODE /* u8 */ // 1
	ATTR_PC         /* u64 */
	ATTR_SYMBOL     /* string */
	ATTR_IN_PORT    /* nested */
	ATTR_TIMESTAMP  /* u64 */ // 5
	ATTR_PROTO      /* u16 */
	ATTR_PAYLOAD    /* binary */
	ATTR_PAD
	ATTR_TRUNC_LEN          /* u32 */
	ATTR_ORIG_LEN           /* u32 */ // 10
	ATTR_QUEUE_LEN          /* u32 */
	ATTR_STATS              /* nested */
	ATTR_HW_STATS           /* nested */
	ATTR_ORIGIN             /* u16 */
	ATTR_HW_TRAP_GROUP_NAME /* string */ // 15
	ATTR_HW_TRAP_NAME       /* string */
	ATTR_HW_ENTRIES         /* nested */
	ATTR_HW_ENTRY           /* nested */
	ATTR_HW_TRAP_COUNT      /* u32 */
	ATTR_SW_DROPS           /* flag */ // 20
	ATTR_HW_DROPS           /* flag */
	ATTR_FLOW_ACTION_COOKIE /* binary */
	ATTR_DROP_REASON        /* string */ // New: Drop reason
)

const (
	GRP_ALERT = 1

	// I don't know how to parse SUMMARY mode, so we always
	// use PACKET, which gives us payloads (but requires
	// privileges)
	ALERT_MODE_SUMMARY = 0
	ALERT_MODE_PACKET  = 1

	NATTR_PORT_NETDEV_IFINDEX = 0 /* u32 */
	NATTR_PORT_NETDEV_NAME    = 1 /* string */

	NATTR_STATS_DROPPED = 0

	ORIGIN_SW = 0
	ORIGIN_HW = 1

	CFG_ALERT_COUNT = 1
	CFG_ALERT_DELAY = 2
)

// Session wraps a genetlink.Conn and looks up the DM_NET family
// from the generic netlink registry
type Session struct {
	conn  *genetlink.Conn
	fam   uint16
	group uint32
	links map[uint32]string
}

// NewSession connects to generic netlink and looks up the DM_NET
// family so we can issue requests
func NewSession(links map[uint32]string) (*Session, error) {
	conn, err := genetlink.Dial(nil)
	if err != nil {
		return nil, fmt.Errorf("session: %w", err)
	}

	s := &Session{
		conn:  conn,
		links: links,
	}

	f, g, err := s.dropMonitorLookup()
	if err != nil {
		return nil, fmt.Errorf("session: %w", err)
	}

	s.fam = f
	s.group = g

	return s, nil
}

// dropMonitorLookup looks up the DM_NET family and group
func (s *Session) dropMonitorLookup() (famid uint16, group uint32, err error) {
	fam, err := s.conn.GetFamily("NET_DM")
	if err != nil {
		return 0, 0, fmt.Errorf("lookup: %w", err)
	}

	if len(fam.Groups) != 1 {
		return 0, 0, fmt.Errorf("lookup: martian NET_DM family (%d groups)", len(fam.Groups))
	}

	return fam.ID, fam.Groups[0].ID, nil
}

// decodeConfig decodes the configuration
func decodeConfig(raw []byte) (map[int]interface{}, error) {
	dec, err := netlink.NewAttributeDecoder(raw)
	if err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}

	ret := map[int]interface{}{}

	for dec.Next() {
		switch dec.Type() {
		case ATTR_ALERT_MODE:
			ret[ATTR_ALERT_MODE] = dec.Uint8()
		case ATTR_TRUNC_LEN:
			ret[ATTR_TRUNC_LEN] = dec.Uint32()
		case ATTR_QUEUE_LEN:
			ret[ATTR_QUEUE_LEN] = dec.Uint32()
		}
	}

	if err := dec.Err(); err != nil {
		return nil, err
	}

	return ret, nil
}

// Config returns the raw attribute bundle of the current DM_NET configuration (see ATTR_ constants)
// Only includes alert mode, packet snapshot length, and queue length
func (s *Session) Config() (map[int]interface{}, error) {
	err := s.req(CMD_CONFIG_GET, nil, false)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}

	ms, _, err := s.conn.Receive()
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}

	conf, err := decodeConfig(ms[0].Data)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}

	return conf, nil
}

// req sends a request to netlink
func (s *Session) req(cmd uint8, data []byte, ack bool) error {
	flags := netlink.Request
	if ack {
		flags |= netlink.Acknowledge
	}

	_, err := s.conn.Send(genetlink.Message{
		Header: genetlink.Header{
			Command: cmd,
		},
		Data: data,
	}, s.fam, flags)
	return err
}

// Start puts DM_NET in packet alert mode (so we get alerts for each packet,
// including the raw contents of the dropped packet), issues an acknowledged CMD_START
// to start monitoring, and then joins the GRP_ALERT netlink multicast group to read alerts.
// DM_NET alerts need to be stopped to work.
func (s *Session) Start(sw, hw bool) error {
	enc := netlink.NewAttributeEncoder()
	enc.Flag(ATTR_SW_DROPS, sw) // Set software drop flag
	enc.Flag(ATTR_HW_DROPS, hw) // Set hardware drop flag
	raw, err := enc.Encode()
	if err != nil {
		return fmt.Errorf("encode: %w", err)
	}

	err = s.setPacketMode() // Set packet mode
	if err != nil {
		return fmt.Errorf("packet mode: %w", err)
	}

	err = s.req(CMD_START, raw, true) // Send start monitoring request
	if err != nil {
		return fmt.Errorf("req: %w", err)
	}

	// Stop alerts if this fails
	_, _, err = s.conn.Receive()
	if err != nil {
		s.Stop(sw, hw)
		return fmt.Errorf("req ack: %w", err)
	}

	err = s.conn.JoinGroup(GRP_ALERT) // Join alert group
	if err != nil {
		s.Stop(sw, hw)
		return fmt.Errorf("join: %w", err)
	}

	return nil
}

// Stop sends an acknowledged CMD_STOP to turn off DM_NET alerts
// (sw is true to disable software drops, hw is true to disable hardware drops),
// and also leaves the GRP_ALERT multicast group.
func (s *Session) Stop(sw, hw bool) error {
	_ = s.conn.LeaveGroup(GRP_ALERT) // Leave alert group

	// BUG(tqbf): Log this, but if we are asking this code to stop, I want it to try to stop.
	// In most cases, we leave the multicast group simply by closing the connection.

	enc := netlink.NewAttributeEncoder()
	enc.Flag(ATTR_SW_DROPS, sw) // Set software drop flag
	enc.Flag(ATTR_HW_DROPS, hw) // Set hardware drop flag
	raw, err := enc.Encode()
	if err != nil {
		return fmt.Errorf("encode: %w", err)
	}

	err = s.req(CMD_STOP, raw, false) // Send stop monitoring request
	if err != nil {
		return fmt.Errorf("req: %w", err)
	}

	return nil
}

// decodeAlert decodes the alert
func decodeAlert(raw []byte) (map[int]interface{}, error) {
	dec, err := netlink.NewAttributeDecoder(raw)
	if err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}

	ret := map[int]interface{}{}

	for dec.Next() {
		switch dec.Type() {
		case ATTR_PC:
			ret[ATTR_PC] = dec.Uint64()
		case ATTR_SYMBOL:
			ret[ATTR_SYMBOL] = dec.String()
		case ATTR_IN_PORT:
			a := map[int]interface{}{}
			dec.Nested(func(d *netlink.AttributeDecoder) error {
				for d.Next() {
					switch d.Type() {
					case NATTR_PORT_NETDEV_IFINDEX:
						a[NATTR_PORT_NETDEV_IFINDEX] = d.Uint32()
					case NATTR_PORT_NETDEV_NAME:
						a[NATTR_PORT_NETDEV_NAME] = d.String()
					}
				}

				return nil
			})
			ret[ATTR_IN_PORT] = a
		case ATTR_TIMESTAMP:
			ret[ATTR_TIMESTAMP] = dec.Uint64()
		case ATTR_PROTO:
			ret[ATTR_PROTO] = dec.Uint16()
		case ATTR_PAYLOAD:
			ret[ATTR_PAYLOAD] = dec.Bytes()
		case ATTR_ORIG_LEN:
			ret[ATTR_ORIG_LEN] = dec.Uint32()
		case ATTR_ORIGIN:
			ret[ATTR_ORIGIN] = dec.Uint16()
		case ATTR_HW_TRAP_GROUP_NAME:
		case ATTR_HW_TRAP_NAME:
		case ATTR_HW_ENTRIES:
		case ATTR_HW_ENTRY:
		case ATTR_HW_TRAP_COUNT:
		case ATTR_FLOW_ACTION_COOKIE:
		case ATTR_DROP_REASON: // New: Handle drop reason
			ret[ATTR_DROP_REASON] = dec.String() // Assuming ATTR_DROP_REASON is defined
		}
	}

	if err := dec.Err(); err != nil {
		return nil, err
	}

	return ret, nil
}

// setPacketMode sets the packet mode
func (s *Session) setPacketMode() error {
	enc := netlink.NewAttributeEncoder()
	enc.Uint8(ATTR_ALERT_MODE, ALERT_MODE_PACKET) // Set alert mode to packet
	enc.Uint32(ATTR_TRUNC_LEN, 100)               // Set truncation length
	enc.Uint32(ATTR_QUEUE_LEN, 4096)              // Set queue length

	raw, err := enc.Encode()
	if err != nil {
		return fmt.Errorf("encode: %w", err)
	}

	err = s.req(CMD_CONFIG, raw, true) // Send configuration request
	if err != nil {
		return fmt.Errorf("req: %w", err)
	}

	_, _, err = s.conn.Receive() // Wait for acknowledgment
	if err != nil {
		return fmt.Errorf("req ack: %w", err)
	}

	return nil
}

// PacketAlertFunc returns false if we should stop reading drops
type PacketAlertFunc func(PacketAlert) bool

// ReadUntil reads packet alerts until the deadline is reached, calling
// `f` on each alert; if the deadline is zero, reads indefinitely.
func (s *Session) ReadUntil(deadline time.Time, f PacketAlertFunc) error {
	// BUG(tqbf): voodoo; I don't know if this is important
	s.conn.SetReadBuffer(4096) // Set read buffer size

	for {
		if !deadline.IsZero() {
			s.conn.SetReadDeadline(deadline) // Set read deadline
		}
		ms, _, err := s.conn.Receive() // Receive messages
		if err != nil {
			if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
				// We are done reading
				return nil
			}

			return fmt.Errorf("recv: %w", err)
		}

		for _, m := range ms {
			if m.Header.Command != CMD_PACKET_ALERT {
				continue // Only process packet alerts
			}

			pa, err := PacketAlertFromRaw(m.Data) // Create PacketAlert from raw data
			if err != nil {
				return fmt.Errorf("parse alert packet: %w", err)
			}

			if !f(pa) {
				return nil // Stop reading if f returns false
			}
		}
	}
}

// GetOrigin is a helper function to determine the origin of the drop
func GetOrigin(pa *PacketAlert) string {
	origin, ok := pa.attrs[ATTR_ORIGIN]
	if !ok {
		return "unknown" // Return unknown if not found
	}
	if origin.(uint16) == ORIGIN_SW {
		return "software" // Return software if software drop
	}
	return "hardware" // Otherwise return hardware
}

// GetDropReason is a helper function to determine the drop reason
func GetDropReason(pa *PacketAlert) string {
	// Check if drop reason attribute is available
	reason, ok := pa.attrs[ATTR_DROP_REASON] // Assuming ATTR_DROP_REASON is defined
	if ok {
		return reason.(string) // Return specific drop reason
	}

	// Return static reason if not available
	return "UNSUPPORTED_FEATURE" // Return unsupported feature
}

// PacketAlert wraps the Netlink attributes parsed from a CMD_ALERT message
type PacketAlert struct {
	attrs map[int]interface{}
}

// PacketAlertFromRaw creates a PacketAlert from the raw bytes of a CMD_ALERT message.
func PacketAlertFromRaw(raw []byte) (PacketAlert, error) {
	attrs, err := decodeAlert(raw) // Decode alert
	if err != nil {
		return PacketAlert{}, fmt.Errorf("decode: %w", err)
	}

	return PacketAlert{
		attrs: attrs,
	}, nil
}

// Packet returns the (truncated) raw bytes of the dropped packet, starting from the link layer header
// (which might be an Ethernet header?).
func (pa *PacketAlert) Packet() []byte {
	payload, ok := pa.attrs[ATTR_PAYLOAD]
	if !ok {
		return nil
	}

	return payload.([]byte) // Return payload
}

// L3Packet returns the (truncated) raw bytes of the dropped packet, skipping the link layer header
// (i.e., starting from the IP packet's IP header)
func (pa *PacketAlert) L3Packet() []byte {
	packet := pa.Packet()
	if len(packet) <= 14 {
		return nil // Return nil if packet length is less than or equal to 14
	}

	return packet[14:] // Return packet skipping link layer header
}

// Symbol returns the kernel function where the drop occurred, when available.
func (pa *PacketAlert) Symbol() string {
	sym, ok := pa.attrs[ATTR_SYMBOL]
	if !ok {
		return "" // Return empty string if not found
	}

	return sym.(string) // Return symbol
}

// PC returns the $RIP of the CPU when the drop occurred, for later resolution to a symbol.
func (pa *PacketAlert) PC() uint64 {
	pc, ok := pa.attrs[ATTR_PC]
	if !ok {
		return 0 // Return 0 if not found
	}

	return pc.(uint64) // Return program counter
}

// Proto returns the layer 3 protocol of the dropped packet.
func (pa *PacketAlert) Proto() uint16 {
	proto, ok := pa.attrs[ATTR_PROTO]
	if !ok {
		return 0 // Return 0 if not found
	}

	return proto.(uint16) // Return protocol
}

// Is4 is true if the dropped packet is an IPv4 packet.
func (pa *PacketAlert) Is4() bool {
	return pa.Proto() == 0x0800 // Check if protocol is IPv4
}

// Is16 is true if the dropped packet is an IPv6 packet.
func (pa *PacketAlert) Is16() bool {
	return pa.Proto() == 0x86DD // Check if protocol is IPv6
}

// Length returns the original non-truncated length of the dropped packet.
func (pa *PacketAlert) Length() uint32 {
	l, ok := pa.attrs[ATTR_ORIG_LEN]
	if !ok {
		return 0
	}

	return l.(uint32)
}

// Link returns the interface index of the dropped packet
func (pa *PacketAlert) Link() uint32 {
	l, ok := pa.attrs[ATTR_IN_PORT]
	if !ok {
		return 0
	}

	a := l.(map[int]interface{})
	lidx, ok := a[NATTR_PORT_NETDEV_IFINDEX]
	if !ok {
		return 0
	}

	return lidx.(uint32) // Return interface index
}

func (pa *PacketAlert) Output(links map[uint32]string) {
	// Log drop information
	iface := fmt.Sprintf("%d", pa.Link())
	if links != nil {
		iface = links[pa.Link()]
	}
	log.Printf("drop at: %s:%016x", pa.Symbol(), pa.PC())
	log.Printf("iface: %s", iface)
	log.Printf("timestamp: %s",
		time.Unix(0, int64(pa.attrs[ATTR_TIMESTAMP].(uint64))).Format("2006-01-02 15:04:05.000000"))
	log.Printf("protocol: %s(0x%x)", EthTypeToString(pa.Proto()), pa.Proto())
	log.Printf("drop reason: %s", GetDropReason(pa))
	log.Printf("origin: %s", GetOrigin(pa))
	log.Printf("length: %d", pa.Length())
}
