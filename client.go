package vmess

import (
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"hash/fnv"
	"io"
	mRand "math/rand"
	"net"
	"time"

	"github.com/getlantern/sing-vmess/buf"
	"github.com/getlantern/sing-vmess/bufio"
	N "github.com/getlantern/sing-vmess/network"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/gofrs/uuid/v5"
)

type Client struct {
	key                 [16]byte
	security            byte
	globalPadding       bool
	authenticatedLength bool
	time                TimeFunc
	alterId             int
	alterKey            [16]byte
}

func NewClient(userId string, security string, alterId int, options ...ClientOption) (*Client, error) {
	user := uuid.FromStringOrNil(userId)
	if user == uuid.Nil {
		user = uuid.NewV5(user, userId)
	}

	var rawSecurity byte
	switch security {
	case "auto":
		rawSecurity = AutoSecurityType()
	case "none", "zero":
		rawSecurity = SecurityTypeNone
	case "aes-128-cfb":
		rawSecurity = SecurityTypeLegacy
	case "aes-128-gcm":
		rawSecurity = SecurityTypeAes128Gcm
	case "chacha20-poly1305":
		rawSecurity = SecurityTypeChacha20Poly1305
	default:
		return nil, E.Extend(ErrUnsupportedSecurityType, security)
	}
	key, err := Key(user)
	if err != nil {
		return nil, err
	}
	client := &Client{
		key:      key,
		security: rawSecurity,
		time:     time.Now,
		alterId:  alterId,
	}
	if alterId > 0 {
		alter, err := AlterId(&user)
		if err != nil {
			return nil, err
		}
		client.alterKey = *alter
	}
	for _, option := range options {
		option(client)
	}
	return client, nil
}

func (c *Client) DialConn(upstream net.Conn, destination M.Socksaddr) (N.ExtendedConn, error) {
	rawConn, err := c.dialRaw(upstream, CommandTCP, destination)
	if err != nil {
		return nil, err
	}

	conn := &clientConn{rawConn}
	return conn, conn.writeHandshake(nil)
}

func (c *Client) DialEarlyConn(upstream net.Conn, destination M.Socksaddr) N.ExtendedConn {
	rawConn, err := c.dialRaw(upstream, CommandTCP, destination)
	if err != nil {
		return nil
	}
	return &clientConn{rawConn}
}

type PacketConn interface {
	net.Conn
	N.NetPacketConn
}

func (c *Client) DialPacketConn(upstream net.Conn, destination M.Socksaddr) (PacketConn, error) {
	rawConn, err := c.dialRaw(upstream, CommandUDP, destination)
	if err != nil {
		return nil, err
	}
	conn := &clientPacketConn{clientConn{rawConn}, destination}
	return conn, conn.writeHandshake(nil)
}

func (c *Client) DialEarlyPacketConn(upstream net.Conn, destination M.Socksaddr) (PacketConn, error) {
	rawConn, err := c.dialRaw(upstream, CommandUDP, destination)
	if err != nil {
		return nil, err
	}
	return &clientPacketConn{clientConn{rawConn}, destination}, nil
}

func (c *Client) DialXUDPPacketConn(upstream net.Conn, destination M.Socksaddr) (PacketConn, error) {
	rawConn, err := c.dialRaw(upstream, CommandMux, destination)
	if err != nil {
		return nil, err
	}
	conn := &clientConn{rawConn}
	err = conn.writeHandshake(nil)
	if err != nil {
		return nil, err
	}
	return NewXUDPConn(conn, destination), nil
}

func (c *Client) DialEarlyXUDPPacketConn(upstream net.Conn, destination M.Socksaddr) (PacketConn, error) {
	rawConn, err := c.dialRaw(upstream, CommandMux, destination)
	if err != nil {
		return nil, err
	}
	return NewXUDPConn(&clientConn{rawConn}, destination), nil
}

type rawClientConn struct {
	*Client
	net.Conn
	command     byte
	security    byte
	option      byte
	destination M.Socksaddr

	requestKey     [16]byte
	requestNonce   [16]byte
	responseHeader byte

	readBuffer bool
	reader     N.ExtendedReader
	writer     N.ExtendedWriter
}

func (c *Client) dialRaw(upstream net.Conn, command byte, destination M.Socksaddr) (*rawClientConn, error) {
	conn := &rawClientConn{
		Client:      c,
		Conn:        upstream,
		command:     command,
		destination: destination,
	}
	_, err := io.ReadFull(rand.Reader, conn.requestKey[:])
	if err != nil {
		return nil, err
	}
	_, err = io.ReadFull(rand.Reader, conn.requestNonce[:])
	if err != nil {
		return nil, err
	}

	security := c.security
	var option byte

	switch security {
	case SecurityTypeNone:
		if command == CommandUDP {
			option = RequestOptionChunkStream
		}
	case SecurityTypeLegacy:
		option = RequestOptionChunkStream
	case SecurityTypeAes128Gcm, SecurityTypeChacha20Poly1305:
		option = RequestOptionChunkStream | RequestOptionChunkMasking
		if c.globalPadding {
			option |= RequestOptionGlobalPadding
		}
		if c.authenticatedLength {
			option |= RequestOptionAuthenticatedLength
		}
	}

	if option&RequestOptionChunkStream != 0 && command == CommandTCP || command == CommandMux {
		conn.readBuffer = true
	}

	conn.security = security
	conn.option = option
	return conn, nil
}

func (c *rawClientConn) NeedHandshake() bool {
	return c.writer == nil
}

func (c *rawClientConn) writeHandshake(payload []byte) error {
	paddingLen := mRand.Intn(16)

	var headerLen int
	headerLen += 1  // version
	headerLen += 16 // request iv
	headerLen += 16 // request key
	headerLen += 1  // response header
	headerLen += 1  // option
	headerLen += 1  // padding<<4 || security
	headerLen += 1  // reversed
	headerLen += 1  // command
	if c.command != CommandMux {
		headerLen += AddressSerializer.AddrPortLen(c.destination)
	}
	headerLen += paddingLen
	headerLen += 4 // fnv1a hash

	if c.alterId > 0 {
		var requestLen int
		requestLen += 16 // alter id
		requestLen += headerLen

		requestBuffer := buf.NewSize(requestLen)
		defer requestBuffer.Release()

		timestamp := uint64(c.time().Unix())
		idHash := hmac.New(md5.New, c.alterKey[:])
		err := binary.Write(idHash, binary.BigEndian, timestamp)
		if err != nil {
			return err
		}
		b, err := requestBuffer.Extend(md5.Size)
		if err != nil {
			return err
		}
		idHash.Sum(b[:0])

		b, err = requestBuffer.Extend(headerLen)
		if err != nil {
			return err
		}
		headerBuffer := buf.With(b)
		err = c.encodeHeader(headerBuffer, paddingLen)
		if err != nil {
			return err
		}

		timeHash := md5.New()
		err = binary.Write(timeHash, binary.BigEndian, timestamp)
		if err != nil {
			return err
		}
		err = binary.Write(timeHash, binary.BigEndian, timestamp)
		if err != nil {
			return err
		}
		err = binary.Write(timeHash, binary.BigEndian, timestamp)
		if err != nil {
			return err
		}
		err = binary.Write(timeHash, binary.BigEndian, timestamp)
		if err != nil {
			return err
		}
		aesStream, err := newAesStream(c.key[:], timeHash.Sum(nil), cipher.NewCFBEncrypter)
		if err != nil {
			return err
		}
		aesStream.XORKeyStream(headerBuffer.Bytes(), headerBuffer.Bytes())

		var writer io.Writer
		var bufferedWriter *bufio.BufferedWriter
		if len(payload) > 0 {
			bufferedWriter = bufio.NewBufferedWriter(c.Conn, buf.New())
			_, err = bufferedWriter.Write(requestBuffer.Bytes())
			writer = bufferedWriter
		} else {
			writer = c.Conn
			_, err = c.Conn.Write(requestBuffer.Bytes())
		}
		if err != nil {
			return err
		}
		w, err := CreateWriter(writer, nil, c.requestKey[:], c.requestNonce[:], c.requestKey[:], c.requestNonce[:], c.security, c.option)
		if err != nil {
			return err
		}
		c.writer = bufio.NewExtendedWriter(w)
		if len(payload) > 0 {
			_, err = c.writer.Write(payload)
			if err != nil {
				return err
			}
			err = bufferedWriter.Fallthrough()
			if err != nil {
				return err
			}
		}
	} else {
		const headerLenBufferLen = 2 + CipherOverhead

		var requestLen int
		requestLen += 16 // auth id
		requestLen += headerLenBufferLen
		requestLen += 8 // connection nonce
		requestLen += headerLen + CipherOverhead

		requestBuffer := buf.NewSize(requestLen)
		defer requestBuffer.Release()

		AuthID(c.key, c.time(), requestBuffer)
		authId := requestBuffer.Bytes()

		b, err := requestBuffer.Extend(headerLenBufferLen)
		if err != nil {
			return err
		}
		headerLenBuffer := buf.With(b)
		connectionNonce, err := requestBuffer.WriteRandom(8)
		if err != nil {
			return err
		}

		err = binary.Write(headerLenBuffer, binary.BigEndian, uint16(headerLen))
		if err != nil {
			return err
		}
		lengthKey := KDF(c.key[:], KDFSaltConstVMessHeaderPayloadLengthAEADKey, authId, connectionNonce)[:16]
		lengthNonce := KDF(c.key[:], KDFSaltConstVMessHeaderPayloadLengthAEADIV, authId, connectionNonce)[:12]
		gcm, err := newAesGcm(lengthKey)
		if err != nil {
			return err
		}
		gcm.Seal(headerLenBuffer.Index(0), lengthNonce, headerLenBuffer.Bytes(), authId)

		b, err = requestBuffer.Extend(headerLen + CipherOverhead)
		if err != nil {
			return err
		}
		headerBuffer := buf.With(b)
		c.encodeHeader(headerBuffer, paddingLen)
		headerKey := KDF(c.key[:], KDFSaltConstVMessHeaderPayloadAEADKey, authId, connectionNonce)[:16]
		headerNonce := KDF(c.key[:], KDFSaltConstVMessHeaderPayloadAEADIV, authId, connectionNonce)[:12]
		gcm, err = newAesGcm(headerKey)
		if err != nil {
			return err
		}
		gcm.Seal(headerBuffer.Index(0), headerNonce, headerBuffer.Bytes(), authId)

		var writer io.Writer
		var bufferedWriter *bufio.BufferedWriter
		if len(payload) > 0 {
			bufferedWriter = bufio.NewBufferedWriter(c.Conn, buf.New())
			writer = bufferedWriter
		} else {
			writer = c.Conn
		}
		_, err = writer.Write(requestBuffer.Bytes())
		if err != nil {
			return err
		}
		w, err := CreateWriter(writer, nil, c.requestKey[:], c.requestNonce[:], c.requestKey[:], c.requestNonce[:], c.security, c.option)
		if err != nil {
			return err
		}
		c.writer = bufio.NewExtendedWriter(w)
		if len(payload) > 0 {
			_, err = c.writer.Write(payload)
			if err != nil {
				return err
			}
			err = bufferedWriter.Fallthrough()
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (c *rawClientConn) encodeHeader(headerBuffer *buf.Buffer, paddingLen int) error {
	err := headerBuffer.WriteByte(Version)
	if err != nil {
		return err
	}
	_, err = headerBuffer.Write(c.requestNonce[:])
	if err != nil {
		return err
	}

	_, err = headerBuffer.Write(c.requestKey[:])
	if err != nil {
		return err
	}
	tmp, err := headerBuffer.WriteRandom(1)
	if err != nil {
		return err
	}
	c.responseHeader = tmp[0]
	if err != nil {
		return err
	}
	err = headerBuffer.WriteByte(c.option)
	if err != nil {
		return err
	}
	err = headerBuffer.WriteByte(byte(paddingLen<<4) | c.security)
	if err != nil {
		return err
	}
	err = headerBuffer.WriteZero()
	if err != nil {
		return err
	}
	err = headerBuffer.WriteByte(c.command)
	if err != nil {
		return err
	}
	if c.command != CommandMux {
		err := AddressSerializer.WriteAddrPort(headerBuffer, c.destination)
		if err != nil {
			return err
		}
	}
	if paddingLen > 0 {
		headerBuffer.Extend(paddingLen)
	}
	headerHash := fnv.New32a()
	_, err = headerHash.Write(headerBuffer.Bytes())
	if err != nil {
		return err
	}
	b, err := headerBuffer.Extend(4)
	if err != nil {
		return err
	}
	headerHash.Sum(b[:0])
	return nil
}

func (c *rawClientConn) readResponse() error {
	if c.alterId > 0 {
		responseKey := md5.Sum(c.requestKey[:])
		responseIv := md5.Sum(c.requestNonce[:])

		headerReader, err := NewStreamReader(c.Conn, responseKey[:], responseIv[:])
		if err != nil {
			return err
		}
		response := buf.NewSize(4)
		defer response.Release()
		_, err = response.ReadFullFrom(headerReader, response.FreeLen())
		if err != nil {
			return err
		}

		if response.Byte(0) != c.responseHeader {
			return E.New("bad response header")
		}
		cmdLen := response.Byte(3)
		if cmdLen > 0 {
			_, err = io.CopyN(io.Discard, c.Conn, int64(cmdLen))
			if err != nil {
				return err
			}
		}

		reader, err := CreateReader(c.Conn, headerReader, c.requestKey[:], c.requestNonce[:], responseKey[:], responseIv[:], c.security, c.option)
		if err != nil {
			return err
		}
		if c.readBuffer {
			reader = bufio.NewChunkReader(reader, ReadChunkSize)
		}
		c.reader = bufio.NewExtendedReader(reader)
	} else {
		_responseKey := sha256.Sum256(c.requestKey[:])
		responseKey := _responseKey[:16]
		_responseNonce := sha256.Sum256(c.requestNonce[:])
		responseNonce := _responseNonce[:16]

		headerLenKey := KDF(responseKey, KDFSaltConstAEADRespHeaderLenKey)[:16]
		headerLenNonce := KDF(responseNonce, KDFSaltConstAEADRespHeaderLenIV)[:12]
		headerLenCipher, err := newAesGcm(headerLenKey)
		if err != nil {
			return err
		}

		headerLenBuffer := buf.NewSize(2 + CipherOverhead)
		defer headerLenBuffer.Release()

		_, err = headerLenBuffer.ReadFullFrom(c.Conn, headerLenBuffer.FreeLen())
		if err != nil {
			return err
		}

		_, err = headerLenCipher.Open(headerLenBuffer.Index(0), headerLenNonce, headerLenBuffer.Bytes(), nil)
		if err != nil {
			return err
		}

		var headerLen uint16
		err = binary.Read(headerLenBuffer, binary.BigEndian, &headerLen)
		if err != nil {
			return err
		}

		headerKey := KDF(responseKey, KDFSaltConstAEADRespHeaderPayloadKey)[:16]
		headerNonce := KDF(responseNonce, KDFSaltConstAEADRespHeaderPayloadIV)[:12]
		headerCipher, err := newAesGcm(headerKey)
		if err != nil {
			return err
		}

		headerBuffer := buf.NewSize(int(headerLen) + CipherOverhead)
		defer headerBuffer.Release()

		_, err = headerBuffer.ReadFullFrom(c.Conn, headerBuffer.FreeLen())
		if err != nil {
			return err
		}

		_, err = headerCipher.Open(headerBuffer.Index(0), headerNonce, headerBuffer.Bytes(), nil)
		if err != nil {
			return err
		}
		headerBuffer.Truncate(int(headerLen))

		reader, err := CreateReader(c.Conn, nil, c.requestKey[:], c.requestNonce[:], responseKey, responseNonce, c.security, c.option)
		if err != nil {
			return err
		}
		if c.readBuffer {
			reader = bufio.NewChunkReader(reader, ReadChunkSize)
		}
		c.reader = bufio.NewExtendedReader(reader)
	}
	return nil
}

func (c *rawClientConn) Close() error {
	return common.Close(
		c.Conn,
		c.reader,
	)
}

func (c *rawClientConn) FrontHeadroom() int {
	return MaxFrontHeadroom
}

func (c *rawClientConn) RearHeadroom() int {
	return MaxRearHeadroom
}

func (c *rawClientConn) NeedAdditionalReadDeadline() bool {
	return true
}

func (c *rawClientConn) Upstream() any {
	return c.Conn
}

type clientConn struct {
	*rawClientConn
}

func (c *clientConn) Read(p []byte) (n int, err error) {
	if c.reader == nil {
		err = c.readResponse()
		if err != nil {
			return
		}
	}
	return c.reader.Read(p)
}

func (c *clientConn) Write(p []byte) (n int, err error) {
	if c.writer == nil {
		err = c.writeHandshake(p)
		if err == nil {
			n = len(p)
		}
		return
	}
	return c.writer.Write(p)
}

func (c *clientConn) ReadBuffer(buffer *buf.Buffer) error {
	if c.reader == nil {
		err := c.readResponse()
		if err != nil {
			return err
		}
	}
	return c.reader.ReadBuffer(buffer)
}

func (c *clientConn) WriteBuffer(buffer *buf.Buffer) error {
	if c.writer == nil {
		return c.writeHandshake(buffer.Bytes())
	}
	return c.writer.WriteBuffer(buffer)
}

/*func (c *clientConn) ReadFrom(r io.Reader) (n int64, err error) {
	if c.writer == nil {
		err = c.writeHandshake(nil)
		if err != nil {
			return
		}
	}
	return bufio.Copy(c.writer, r)
}*/

func (c *clientConn) WriteTo(w io.Writer) (n int64, err error) {
	if c.reader == nil {
		err = c.readResponse()
		if err != nil {
			return
		}
	}
	return bufio.Copy(w, c.reader)
}

type clientPacketConn struct {
	clientConn
	destination M.Socksaddr
}

func (c *clientPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	if c.reader == nil {
		err = c.readResponse()
		if err != nil {
			return
		}
	}
	n, err = c.reader.Read(p)
	if err != nil {
		return
	}
	addr = c.destination.UDPAddr()
	return
}

func (c *clientPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	if c.writer == nil {
		err = c.writeHandshake(nil)
		if err != nil {
			return
		}
	}
	return c.writer.Write(p)
}

func (c *clientPacketConn) ReadPacket(buffer *buf.Buffer) (destination M.Socksaddr, err error) {
	if c.reader == nil {
		err = c.readResponse()
		if err != nil {
			return
		}
	}
	err = c.reader.ReadBuffer(buffer)
	if err != nil {
		return
	}
	destination = c.destination
	return
}

func (c *clientPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	if c.writer == nil {
		err := c.writeHandshake(nil)
		if err != nil {
			buffer.Release()
			return err
		}
	}
	return c.writer.WriteBuffer(buffer)
}
