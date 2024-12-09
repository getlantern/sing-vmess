package packetaddr

import (
	"net"

	"github.com/getlantern/sing-vmess/buf"
	"github.com/getlantern/sing-vmess/bufio"
	N "github.com/getlantern/sing-vmess/network"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

type PacketConn struct {
	N.NetPacketConn
	bindAddr M.Socksaddr
}

func NewConn(conn net.PacketConn, bindAddr M.Socksaddr) *PacketConn {
	return &PacketConn{
		bufio.NewPacketConn(conn),
		bindAddr,
	}
}

func NewBindConn(conn net.Conn) *PacketConn {
	return &PacketConn{
		bufio.NewUnbindPacketConn(conn),
		M.Socksaddr{},
	}
}

func (c *PacketConn) RemoteAddr() net.Addr {
	return c.bindAddr
}

func (c *PacketConn) Read(b []byte) (n int, err error) {
	n, _, err = c.ReadFrom(b)
	return
}

func (c *PacketConn) Write(b []byte) (n int, err error) {
	return c.WriteTo(b, c.RemoteAddr())
}

func (c *PacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	buffer := buf.With(p)
	var destination M.Socksaddr
	destination, err = c.ReadPacket(buffer)
	if err != nil {
		return
	}
	n = copy(p, buffer.Bytes())
	if destination.IsFqdn() {
		addr = destination
	} else {
		addr = destination.UDPAddr()
	}
	return
}

func (c *PacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	destination := M.SocksaddrFromNet(addr)
	buffer := buf.NewSize(AddressSerializer.AddrPortLen(destination) + len(p))
	defer buffer.Release()
	err = AddressSerializer.WriteAddrPort(buffer, destination)
	if err != nil {
		return
	}
	_, err = buffer.Write(p)
	if err != nil {
		return 0, err
	}
	return c.NetPacketConn.WriteTo(buffer.Bytes(), c.bindAddr.UDPAddr())
}

func (c *PacketConn) ReadPacket(buffer *buf.Buffer) (destination M.Socksaddr, err error) {
	_, err = c.NetPacketConn.ReadPacket(buffer)
	if err != nil {
		return
	}
	destination, err = AddressSerializer.ReadAddrPort(buffer)
	if err != nil {
		return
	}
	return destination.Unwrap(), nil
}

func (c *PacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	if destination.IsFqdn() {
		return E.Extend(ErrFqdnUnsupported, destination.Fqdn)
	}
	b, err := buffer.ExtendHeader(AddressSerializer.AddrPortLen(destination))
	if err != nil {
		return err
	}
	header := buf.With(b)
	err = AddressSerializer.WriteAddrPort(header, destination)
	if err != nil {
		return err
	}
	return c.NetPacketConn.WritePacket(buffer, c.bindAddr)
}

func (c *PacketConn) FrontHeadroom() int {
	return M.MaxIPSocksaddrLength
}

func (c *PacketConn) Upstream() any {
	return c.NetPacketConn
}
