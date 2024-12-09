package bufio

import (
	"github.com/getlantern/sing-vmess/buf"
	N "github.com/getlantern/sing-vmess/network"
	M "github.com/sagernet/sing/common/metadata"
)

func (c *bidirectionalNATPacketConn) CreatePacketReadWaiter() (N.PacketReadWaiter, bool) {
	waiter, created := CreatePacketReadWaiter(c.NetPacketConn)
	if !created {
		return nil, false
	}
	return &waitBidirectionalNATPacketConn{c, waiter}, true
}

type waitBidirectionalNATPacketConn struct {
	*bidirectionalNATPacketConn
	readWaiter N.PacketReadWaiter
}

func (c *waitBidirectionalNATPacketConn) InitializeReadWaiter(options N.ReadWaitOptions) (needCopy bool) {
	return c.readWaiter.InitializeReadWaiter(options)
}

func (c *waitBidirectionalNATPacketConn) WaitReadPacket() (buffer *buf.Buffer, destination M.Socksaddr, err error) {
	buffer, destination, err = c.readWaiter.WaitReadPacket()
	if err != nil {
		return
	}
	if socksaddrWithoutPort(destination) == c.origin {
		destination = M.Socksaddr{
			Addr: c.destination.Addr,
			Fqdn: c.destination.Fqdn,
			Port: destination.Port,
		}
	}
	return
}
