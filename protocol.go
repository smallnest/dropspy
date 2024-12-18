package dropspy

// Third layer protocol
const (
	ETH_P_LOOP      = 0x0060 // Ethernet Loopback packet
	ETH_P_PUP       = 0x0200 // Xerox PUP packet
	ETH_P_PUPAT     = 0x0201 // Xerox PUP Addr Trans packet
	ETH_P_TSN       = 0x22F0 // TSN (IEEE 1722) packet
	ETH_P_ERSPAN2   = 0x22EB // ERSPAN version 2 (type III)
	ETH_P_IP        = 0x0800 // Internet Protocol packet
	ETH_P_X25       = 0x0805 // CCITT X.25
	ETH_P_ARP       = 0x0806 // Address Resolution packet
	ETH_P_BPQ       = 0x08FF // G8BPQ AX.25 Ethernet Packet [ NOT AN OFFICIALLY REGISTERED ID ]
	ETH_P_IEEEPUP   = 0x0a00 // Xerox IEEE802.3 PUP packet
	ETH_P_IEEEPUPAT = 0x0a01 // Xerox IEEE802.3 PUP Addr Trans packet
	ETH_P_BATMAN    = 0x4305 // B.A.T.M.A.N.-Advanced packet [ NOT AN OFFICIALLY REGISTERED ID ]
	ETH_P_DEC       = 0x6000 // DEC Assigned proto
	ETH_P_DNA_DL    = 0x6001 // DEC DNA Dump/Load
	ETH_P_DNA_RC    = 0x6002 // DEC DNA Remote Console
	ETH_P_DNA_RT    = 0x6003 // DEC DNA Routing
	ETH_P_LAT       = 0x6004 // DEC LAT
	ETH_P_DIAG      = 0x6005 // DEC Diagnostics
	ETH_P_CUST      = 0x6006 // DEC Customer use
	ETH_P_SCA       = 0x6007 // DEC Systems Comms Arch
	ETH_P_TEB       = 0x6558 // Trans Ether Bridging
	ETH_P_RARP      = 0x8035 // Reverse Addr Res packet
	ETH_P_ATALK     = 0x809B // Appletalk DDP
	ETH_P_AARP      = 0x80F3 // Appletalk AARP
	ETH_P_8021Q     = 0x8100 // 802.1Q VLAN Extended Header
	ETH_P_ERSPAN    = 0x88BE // ERSPAN type II
	ETH_P_IPX       = 0x8137 // IPX over DIX
	ETH_P_IPV6      = 0x86DD // IPv6 over bluebook
	ETH_P_PAUSE     = 0x8808 // IEEE Pause frames. See 802.3 31B
	ETH_P_SLOW      = 0x8809 // Slow Protocol. See 802.3ad 43B
	ETH_P_WCCP      = 0x883E // Web-cache coordination protocol defined in draft-wilson-wrec-wccp-v2-00.txt
	ETH_P_MPLS_UC   = 0x8847 // MPLS Unicast traffic
	ETH_P_MPLS_MC   = 0x8848 // MPLS Multicast traffic
	ETH_P_ATMMPOA   = 0x884c // MultiProtocol Over ATM
	ETH_P_PPP_DISC  = 0x8863 // PPPoE discovery messages
	ETH_P_PPP_SES   = 0x8864 // PPPoE session messages
	ETH_P_LINK_CTL  = 0x886c // HPNA, wlan link local tunnel
	ETH_P_ATMFATE   = 0x8884 // Frame-based ATM Transport over Ethernet
	ETH_P_PAE       = 0x888E // Port Access Entity (IEEE 802.1X)
	ETH_P_PROFINET  = 0x8892 // PROFINET
	ETH_P_REALTEK   = 0x8899 // Multiple proprietary protocols
	ETH_P_AOE       = 0x88A2 // ATA over Ethernet
	ETH_P_ETHERCAT  = 0x88A4 // EtherCAT
	ETH_P_8021AD    = 0x88A8 // 802.1ad Service VLAN
	ETH_P_802_EX1   = 0x88B5 // 802.1 Local Experimental 1.
	ETH_P_PREAUTH   = 0x88C7 // 802.11 Preauthentication
	ETH_P_TIPC      = 0x88CA // TIPC
	ETH_P_LLDP      = 0x88CC // Link Layer Discovery Protocol
	ETH_P_MRP       = 0x88E3 // Media Redundancy Protocol
	ETH_P_MACSEC    = 0x88E5 // 802.1ae MACsec
	ETH_P_8021AH    = 0x88E7 // 802.1ah Backbone Service Tag
	ETH_P_MVRP      = 0x88F5 // 802.1Q MVRP
	ETH_P_1588      = 0x88F7 // IEEE 1588 Timesync
	ETH_P_NCSI      = 0x88F8 // NCSI protocol
	ETH_P_PRP       = 0x88FB // IEC 62439-3 PRP/HSRv0
	ETH_P_CFM       = 0x8902 // Connectivity Fault Management
	ETH_P_FCOE      = 0x8906 // Fibre Channel over Ethernet
	ETH_P_IBOE      = 0x8915 // Infiniband over Ethernet
	ETH_P_TDLS      = 0x890D // TDLS
	ETH_P_FIP       = 0x8914 // FCoE Initialization Protocol
	ETH_P_80221     = 0x8917 // IEEE 802.21 Media Independent Handover Protocol
	ETH_P_HSR       = 0x892F // IEC 62439-3 HSRv1
	ETH_P_NSH       = 0x894F // Network Service Header
	ETH_P_LOOPBACK  = 0x9000 // Ethernet loopback packet, per IEEE 802.3
	ETH_P_QINQ1     = 0x9100 // deprecated QinQ VLAN [ NOT AN OFFICIALLY REGISTERED ID ]
	ETH_P_QINQ2     = 0x9200 // deprecated QinQ VLAN [ NOT AN OFFICIALLY REGISTERED ID ]
	ETH_P_QINQ3     = 0x9300 // deprecated QinQ VLAN [ NOT AN OFFICIALLY REGISTERED ID ]
	ETH_P_EDSA      = 0xDADA // Ethertype DSA [ NOT AN OFFICIALLY REGISTERED ID ]
	ETH_P_DSA_8021Q = 0xDADB // Fake VLAN Header for DSA [ NOT AN OFFICIALLY REGISTERED ID ]
	ETH_P_DSA_A5PSW = 0xE001 // A5PSW Tag Value [ NOT AN OFFICIALLY REGISTERED ID ]
	ETH_P_IFE       = 0xED3E // ForCES inter-FE LFB type
	ETH_P_AF_IUCV   = 0xFBFB // IBM af_iucv [ NOT AN OFFICIALLY REGISTERED ID ]
	ETH_P_802_3_MIN = 0x0600 // If the value in the ethernet type is more than this value then the frame is Ethernet II. Else it is 802.3

	// Non DIX types. Won't clash for 1500 types.
	ETH_P_802_3      = 0x0001 // Dummy type for 802.3 frames
	ETH_P_AX25       = 0x0002 // Dummy protocol id for AX.25
	ETH_P_ALL        = 0x0003 // Every packet (be careful!!!)
	ETH_P_802_2      = 0x0004 // 802.2 frames
	ETH_P_SNAP       = 0x0005 // Internal only
	ETH_P_DDCMP      = 0x0006 // DEC DDCMP: Internal only
	ETH_P_WAN_PPP    = 0x0007 // Dummy type for WAN PPP frames
	ETH_P_PPP_MP     = 0x0008 // Dummy type for PPP MP frames
	ETH_P_LOCALTALK  = 0x0009 // Localtalk pseudo type
	ETH_P_CAN        = 0x000C // CAN: Controller Area Network
	ETH_P_CANFD      = 0x000D // CANFD: CAN flexible data rate
	ETH_P_CANXL      = 0x000E // CANXL: eXtended frame Length
	ETH_P_PPPTALK    = 0x0010 // Dummy type for Atalk over PPP
	ETH_P_TR_802_2   = 0x0011 // 802.2 frames
	ETH_P_MOBITEX    = 0x0015 // Mobitex (kaz@cafe.net)
	ETH_P_CONTROL    = 0x0016 // Card specific control frames
	ETH_P_IRDA       = 0x0017 // Linux-IrDA
	ETH_P_ECONET     = 0x0018 // Acorn Econet
	ETH_P_HDLC       = 0x0019 // HDLC frames
	ETH_P_ARCNET     = 0x001A // 1A for ArcNet :-)
	ETH_P_DSA        = 0x001B // Distributed Switch Arch.
	ETH_P_TRAILER    = 0x001C // Trailer switch tagging
	ETH_P_PHONET     = 0x00F5 // Nokia Phonet frames
	ETH_P_IEEE802154 = 0x00F6 // IEEE802.15.4 frame
	ETH_P_CAIF       = 0x00F7 // ST-Ericsson CAIF protocol
	ETH_P_XDSA       = 0x00F8 // Multiplexed DSA protocol
	ETH_P_MAP        = 0x00F9 // Qualcomm multiplexing and aggregation protocol
	ETH_P_MCTP       = 0x00FA // Management component transport protocol packets
)

var ethTypeToString = map[uint16]string{
	0x0060: "ETH_P_LOOP",
	0x0200: "ETH_P_PUP",
	0x0201: "ETH_P_PUPAT",
	0x22F0: "ETH_P_TSN",
	0x22EB: "ETH_P_ERSPAN2",
	0x0800: "ETH_P_IP",
	0x0805: "ETH_P_X25",
	0x0806: "ETH_P_ARP",
	0x08FF: "ETH_P_BPQ",
	0x0a00: "ETH_P_IEEEPUP",
	0x0a01: "ETH_P_IEEEPUPAT",
	0x4305: "ETH_P_BATMAN",
	0x6000: "ETH_P_DEC",
	0x6001: "ETH_P_DNA_DL",
	0x6002: "ETH_P_DNA_RC",
	0x6003: "ETH_P_DNA_RT",
	0x6004: "ETH_P_LAT",
	0x6005: "ETH_P_DIAG",
	0x6006: "ETH_P_CUST",
	0x6007: "ETH_P_SCA",
	0x6558: "ETH_P_TEB",
	0x8035: "ETH_P_RARP",
	0x809B: "ETH_P_ATALK",
	0x80F3: "ETH_P_AARP",
	0x8100: "ETH_P_8021Q",
	0x88BE: "ETH_P_ERSPAN",
	0x8137: "ETH_P_IPX",
	0x86DD: "ETH_P_IPV6",
	0x8808: "ETH_P_PAUSE",
	0x8809: "ETH_P_SLOW",
	0x883E: "ETH_P_WCCP",
	0x8847: "ETH_P_MPLS_UC",
	0x8848: "ETH_P_MPLS_MC",
	0x884c: "ETH_P_ATMMPOA",
	0x8863: "ETH_P_PPP_DISC",
	0x8864: "ETH_P_PPP_SES",
	0x886c: "ETH_P_LINK_CTL",
	0x8884: "ETH_P_ATMFATE",
	0x888E: "ETH_P_PAE",
	0x8892: "ETH_P_PROFINET",
	0x8899: "ETH_P_REALTEK",
	0x88A2: "ETH_P_AOE",
	0x88A4: "ETH_P_ETHERCAT",
	0x88A8: "ETH_P_8021AD",
	0x88B5: "ETH_P_802_EX1",
	0x88C7: "ETH_P_PREAUTH",
	0x88CA: "ETH_P_TIPC",
	0x88CC: "ETH_P_LLDP",
	0x88E3: "ETH_P_MRP",
	0x88E5: "ETH_P_MACSEC",
	0x88E7: "ETH_P_8021AH",
	0x88F5: "ETH_P_MVRP",
	0x88F7: "ETH_P_1588",
	0x88F8: "ETH_P_NCSI",
	0x88FB: "ETH_P_PRP",
	0x8902: "ETH_P_CFM",
	0x8906: "ETH_P_FCOE",
	0x8915: "ETH_P_IBOE",
	0x890D: "ETH_P_TDLS",
	0x8914: "ETH_P_FIP",
	0x8917: "ETH_P_80221",
	0x892F: "ETH_P_HSR",
	0x894F: "ETH_P_NSH",
	0x9000: "ETH_P_LOOPBACK",
	0x9100: "ETH_P_QINQ1",
	0x9200: "ETH_P_QINQ2",
	0x9300: "ETH_P_QINQ3",
	0xDADA: "ETH_P_EDSA",
	0xDADB: "ETH_P_DSA_8021Q",
	0xE001: "ETH_P_DSA_A5PSW",
	0xED3E: "ETH_P_IFE",
	0xFBFB: "ETH_P_AF_IUCV",
	0x0600: "ETH_P_802_3_MIN",
	0x0001: "ETH_P_802_3",
	0x0002: "ETH_P_AX25",
	0x0003: "ETH_P_ALL",
	0x0004: "ETH_P_802_2",
	0x0005: "ETH_P_SNAP",
	0x0006: "ETH_P_DDCMP",
	0x0007: "ETH_P_WAN_PPP",
	0x0008: "ETH_P_PPP_MP",
	0x0009: "ETH_P_LOCALTALK",
	0x000C: "ETH_P_CAN",
	0x000D: "ETH_P_CANFD",
	0x000E: "ETH_P_CANXL",
	0x0010: "ETH_P_PPPTALK",
	0x0011: "ETH_P_TR_802_2",
	0x0015: "ETH_P_MOBITEX",
	0x0016: "ETH_P_CONTROL",
	0x0017: "ETH_P_IRDA",
	0x0018: "ETH_P_ECONET",
	0x0019: "ETH_P_HDLC",
	0x001A: "ETH_P_ARCNET",
	0x001B: "ETH_P_DSA",
	0x001C: "ETH_P_TRAILER",
	0x00F5: "ETH_P_PHONET",
	0x00F6: "ETH_P_IEEE802154",
	0x00F7: "ETH_P_CAIF",
	0x00F8: "ETH_P_XDSA",
	0x00F9: "ETH_P_MAP",
	0x00FA: "ETH_P_MCTP",
}

func EthTypeToString(ethType uint16) string {
	if name, ok := ethTypeToString[ethType]; ok {
		return name
	}
	return "UNKNOWN"
}
