package dropspy

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/mdlayher/genetlink"
)

func TestHello(t *testing.T) {
	conn, err := genetlink.Dial(nil)
	if err != nil {
		t.Fatalf("dial: %s", err)
	}

	fams, err := conn.ListFamilies()
	if err != nil {
		t.Fatalf("list: %s", err)
	}

	for _, fam := range fams {
		t.Logf("%+v", fam)
	}
}

func TestSession(t *testing.T) {
	s, err := NewSession(nil)
	if err != nil {
		t.Fatalf("init: %s", err)
	}

	conf, err := s.Config()
	if err != nil {
		t.Fatalf("config: %s", err)
	}

	t.Logf("%+v", conf)
}

func TestWatch(t *testing.T) {
	s, err := NewSession(nil)
	if err != nil {
		t.Fatalf("init: %s", err)
	}

	s.Stop(true, true)

	err = s.Start(true, false)
	if err != nil {
		t.Fatalf("start: %s", err)
	}

	defer func() {
		s.Stop(true, true)
	}()

	deadline := time.Now().Add(15 * time.Second)

	err = s.ReadUntil(deadline, func(pa PacketAlert) bool {
		t.Logf("drop at %s:%016x\n%s", pa.Symbol(), pa.PC(), hex.Dump(pa.L3Packet()))

		t.Logf("%+v", pa.attrs[ATTR_IN_PORT])

		return true
	})
	if err != nil {
		t.Fatalf("readuntil: %s", err)
	}
}

func TestLinks(t *testing.T) {
	links, err := LinkList()
	if err != nil {
		t.Fatalf("links: %s", err)
	}

	t.Logf("%+v", links)
}
