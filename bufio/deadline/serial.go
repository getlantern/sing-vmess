package deadline

import (
	"errors"
	"net"
	"sync"

	"github.com/getlantern/sing-vmess/buf"
	N "github.com/getlantern/sing-vmess/network"
	"github.com/sagernet/sing/common/debug"
	M "github.com/sagernet/sing/common/metadata"
)

type SerialConn struct {
	N.ExtendedConn
	access sync.Mutex
}

func NewSerialConn(conn N.ExtendedConn) N.ExtendedConn {
	if !debug.Enabled {
		return conn
	}
	return &SerialConn{ExtendedConn: conn}
}

func (c *SerialConn) Read(p []byte) (n int, err error) {
	if !c.access.TryLock() {
		return 0, errors.New("concurrent read on deadline conn")
	}
	defer c.access.Unlock()
	return c.ExtendedConn.Read(p)
}

func (c *SerialConn) ReadBuffer(buffer *buf.Buffer) error {
	if !c.access.TryLock() {
		return errors.New("concurrent read on deadline conn")
	}
	defer c.access.Unlock()
	return c.ExtendedConn.ReadBuffer(buffer)
}

func (c *SerialConn) Upstream() any {
	return c.ExtendedConn
}

type SerialPacketConn struct {
	N.NetPacketConn
	access sync.Mutex
}

func NewSerialPacketConn(conn N.NetPacketConn) N.NetPacketConn {
	if !debug.Enabled {
		return conn
	}
	return &SerialPacketConn{NetPacketConn: conn}
}

func (c *SerialPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	if !c.access.TryLock() {
		return 0, nil, errors.New("concurrent read on deadline conn")
	}
	defer c.access.Unlock()
	return c.NetPacketConn.ReadFrom(p)
}

func (c *SerialPacketConn) ReadPacket(buffer *buf.Buffer) (destination M.Socksaddr, err error) {
	if !c.access.TryLock() {
		return M.Socksaddr{}, errors.New("concurrent read on deadline conn")
	}
	defer c.access.Unlock()
	return c.NetPacketConn.ReadPacket(buffer)
}

func (c *SerialPacketConn) Upstream() any {
	return c.NetPacketConn
}
