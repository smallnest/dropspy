package dropspy

import (
	"net"
)

// LinkList returns a map from interface index to interface name.
func LinkList() (map[uint32]string, error) {
	ret := map[uint32]string{}

	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, iface := range ifaces {
		ret[uint32(iface.Index)] = iface.Name
	}

	return ret, nil
}
