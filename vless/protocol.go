package vless

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"

	vmess "github.com/getlantern/sing-vmess"
	"github.com/getlantern/sing-vmess/buf"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/rw"
	"github.com/sagernet/sing/common/varbin"
)

const (
	Version    = 0
	FlowVision = "xtls-rprx-vision"
)

type Request struct {
	UUID        [16]byte
	Command     byte
	Destination M.Socksaddr
	Flow        string
}

func ReadRequest(reader io.Reader) (*Request, error) {
	var request Request

	var version uint8
	err := binary.Read(reader, binary.BigEndian, &version)
	if err != nil {
		return nil, err
	}
	if version != Version {
		return nil, E.New("unknown version: ", version)
	}

	_, err = io.ReadFull(reader, request.UUID[:])
	if err != nil {
		return nil, err
	}

	var addonsLen uint8
	err = binary.Read(reader, binary.BigEndian, &addonsLen)
	if err != nil {
		return nil, err
	}

	if addonsLen > 0 {
		addonsBytes := make([]byte, addonsLen)
		_, err = io.ReadFull(reader, addonsBytes)
		if err != nil {
			return nil, err
		}

		addons, err := readAddons(bytes.NewReader(addonsBytes))
		if err != nil {
			return nil, err
		}
		request.Flow = addons.Flow
	}

	err = binary.Read(reader, binary.BigEndian, &request.Command)
	if err != nil {
		return nil, err
	}

	if request.Command != vmess.CommandMux {
		request.Destination, err = vmess.AddressSerializer.ReadAddrPort(reader)
		if err != nil {
			return nil, err
		}
	}

	return &request, nil
}

type Addons struct {
	Flow string
	Seed string
}

// func readAddons(reader varbin.Reader) (*Addons, error) {
func readAddons(reader *bytes.Reader) (*Addons, error) {
	protoHeader, err := reader.ReadByte()
	if err != nil {
		return nil, err
	}
	if protoHeader != 10 {
		return nil, E.New("unknown protobuf message header: ", protoHeader)
	}

	var addons Addons

	flowLen, err := binary.ReadUvarint(reader)
	if err != nil {
		if err == io.EOF {
			return &addons, nil
		}
		return nil, err
	}
	flowBytes := make([]byte, flowLen)
	_, err = io.ReadFull(reader, flowBytes)
	if err != nil {
		return nil, err
	}
	addons.Flow = string(flowBytes)

	seedLen, err := binary.ReadUvarint(reader)
	if err != nil {
		if err == io.EOF {
			return &addons, nil
		}
		return nil, err
	}
	seedBytes := make([]byte, seedLen)
	_, err = io.ReadFull(reader, seedBytes)
	if err != nil {
		return nil, err
	}
	addons.Seed = string(seedBytes)

	return &addons, nil
}

func WriteRequest(writer io.Writer, request Request, payload []byte) error {
	var requestLen int
	requestLen += 1  // version
	requestLen += 16 // uuid
	requestLen += 1  // protobuf length

	var addonsLen int
	if request.Flow != "" {
		addonsLen += 1 // protobuf header
		addonsLen += varbin.UvarintLen(uint64(len(request.Flow)))
		// addonsLen += varbin.UvarintLen(uint64(len(request.Flow)))
		addonsLen += len(request.Flow)
		requestLen += addonsLen
	}
	requestLen += 1 // command
	if request.Command != vmess.CommandMux {
		requestLen += vmess.AddressSerializer.AddrPortLen(request.Destination)
	}
	requestLen += len(payload)
	buffer := buf.NewSize(requestLen)
	defer buffer.Release()
	err := errors.Join(
		buffer.WriteByte(Version),
		common.Error(buffer.Write(request.UUID[:])),
		buffer.WriteByte(byte(addonsLen)),
	)
	if err != nil {
		return err
	}
	if addonsLen > 0 {
		err := buffer.WriteByte(10)
		if err != nil {
			return err
		}
		b, err := buffer.Extend(varbin.UvarintLen(uint64(len(request.Flow))))
		if err != nil {
			return err
		}
		binary.PutUvarint(b, uint64(len(request.Flow)))
		err = common.Error(buffer.WriteString(request.Flow))
		if err != nil {
			return err
		}
	}
	if err = buffer.WriteByte(request.Command); err != nil {
		return err
	}

	if request.Command != vmess.CommandMux {
		err := vmess.AddressSerializer.WriteAddrPort(buffer, request.Destination)
		if err != nil {
			return err
		}
	}

	_, err = buffer.Write(payload)
	if err != nil {
		return err
	}
	return common.Error(writer.Write(buffer.Bytes()))
}

func EncodeRequest(request Request, buffer *buf.Buffer) error {
	var addonsLen int
	if request.Flow != "" {
		addonsLen += 1 // protobuf header
		addonsLen += varbin.UvarintLen(uint64(len(request.Flow)))
		addonsLen += len(request.Flow)
	}
	err := errors.Join(
		buffer.WriteByte(Version),
		common.Error(buffer.Write(request.UUID[:])),
		buffer.WriteByte(byte(addonsLen)),
	)
	if err != nil {
		return err
	}
	if addonsLen > 0 {
		err := buffer.WriteByte(10)
		if err != nil {
			return err
		}
		b, err := buffer.Extend(varbin.UvarintLen(uint64(len(request.Flow))))
		if err != nil {
			return err
		}
		binary.PutUvarint(b, uint64(len(request.Flow)))
		err = common.Error(buffer.WriteString(request.Flow))
		if err != nil {
			return err
		}
	}
	if err = buffer.WriteByte(request.Command); err != nil {
		return err
	}

	if request.Command != vmess.CommandMux {
		err := vmess.AddressSerializer.WriteAddrPort(buffer, request.Destination)
		if err != nil {
			return err
		}
	}
	return nil
}

func RequestLen(request Request) int {
	var requestLen int
	requestLen += 1  // version
	requestLen += 16 // uuid
	requestLen += 1  // protobuf length

	var addonsLen int
	if request.Flow != "" {
		addonsLen += 1 // protobuf header
		addonsLen += varbin.UvarintLen(uint64(len(request.Flow)))
		addonsLen += len(request.Flow)
		requestLen += addonsLen
	}
	requestLen += 1 // command
	if request.Command != vmess.CommandMux {
		requestLen += vmess.AddressSerializer.AddrPortLen(request.Destination)
	}
	return requestLen
}

func WritePacketRequest(writer io.Writer, request Request, payload []byte) error {
	var requestLen int
	requestLen += 1  // version
	requestLen += 16 // uuid
	requestLen += 1  // protobuf length
	var addonsLen int
	/*if request.Flow != "" {
		addonsLen += 1 // protobuf header
		addonsLen += varbin.UvarintLen(uint64(len(request.Flow)))
		addonsLen += len(request.Flow)
		requestLen += addonsLen
	}*/
	requestLen += 1 // command
	requestLen += vmess.AddressSerializer.AddrPortLen(request.Destination)
	if len(payload) > 0 {
		requestLen += 2
		requestLen += len(payload)
	}
	buffer := buf.NewSize(requestLen)
	defer buffer.Release()
	err := errors.Join(
		buffer.WriteByte(Version),
		common.Error(buffer.Write(request.UUID[:])),
		buffer.WriteByte(byte(addonsLen)),
	)
	if err != nil {
		return err
	}

	if addonsLen > 0 {
		err := buffer.WriteByte(10)
		if err != nil {
			return err
		}
		b, err := buffer.Extend(varbin.UvarintLen(uint64(len(request.Flow))))
		if err != nil {
			return err
		}
		binary.PutUvarint(b, uint64(len(request.Flow)))
		err = common.Error(buffer.WriteString(request.Flow))
		if err != nil {
			return err
		}
	}

	err = buffer.WriteByte(vmess.CommandUDP)
	if err != nil {
		return err
	}

	err = vmess.AddressSerializer.WriteAddrPort(buffer, request.Destination)
	if err != nil {
		return err
	}

	if len(payload) > 0 {
		err = errors.Join(
			binary.Write(buffer, binary.BigEndian, uint16(len(payload))),
			common.Error(buffer.Write(payload)),
		)
		if err != nil {
			return err
		}
	}

	return common.Error(writer.Write(buffer.Bytes()))
}

func ReadResponse(reader io.Reader) error {
	var version byte
	err := binary.Read(reader, binary.BigEndian, &version)
	if err != nil {
		return err
	}
	if version != Version {
		return E.New("unknown version: ", version)
	}
	var protobufLength byte
	err = binary.Read(reader, binary.BigEndian, &protobufLength)
	if err != nil {
		return err
	}
	if protobufLength > 0 {
		err = rw.SkipN(reader, int(protobufLength))
		if err != nil {
			return err
		}
	}
	return nil
}
