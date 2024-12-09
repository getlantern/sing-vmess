package vmess

import (
	"encoding/binary"
	"hash/fnv"
	"io"

	"github.com/getlantern/sing-vmess/buf"
	"github.com/getlantern/sing-vmess/bufio"
	N "github.com/getlantern/sing-vmess/network"
	"github.com/sagernet/sing/common"
)

type StreamChecksumReader struct {
	upstream N.ExtendedReader
}

func NewStreamChecksumReader(reader io.Reader) *StreamChecksumReader {
	return &StreamChecksumReader{bufio.NewExtendedReader(reader)}
}

func (r *StreamChecksumReader) Read(p []byte) (n int, err error) {
	n, err = r.upstream.Read(p)
	if err != nil {
		return
	}
	hash := fnv.New32a()
	_, err = hash.Write(p[4:n])
	if err != nil {
		return 0, err
	}
	if hash.Sum32() != binary.BigEndian.Uint32(p) {
		return 0, ErrInvalidChecksum
	}
	n = copy(p, p[4:n])
	return
}

func (r *StreamChecksumReader) ReadBuffer(buffer *buf.Buffer) error {
	err := r.upstream.ReadBuffer(buffer)
	if err != nil {
		return err
	}
	hash := fnv.New32a()
	_, err = hash.Write(buffer.From(4))
	if err != nil {
		return err
	}
	if hash.Sum32() != binary.BigEndian.Uint32(buffer.To(4)) {
		return ErrInvalidChecksum
	}
	buffer.Advance(4)
	return nil
}

func (r *StreamChecksumReader) Upstream() any {
	return r.upstream
}

type StreamChecksumWriter struct {
	upstream *StreamChunkWriter
}

func NewStreamChecksumWriter(upstream *StreamChunkWriter) *StreamChecksumWriter {
	return &StreamChecksumWriter{upstream}
}

func (w *StreamChecksumWriter) Write(p []byte) (n int, err error) {
	hash := fnv.New32a()
	_, err = hash.Write(p)
	if err != nil {
		return 0, err
	}
	return w.upstream.WriteWithChecksum(hash.Sum32(), p)
}

func (w *StreamChecksumWriter) WriteBuffer(buffer *buf.Buffer) error {
	hash := fnv.New32a()
	_, err := hash.Write(buffer.Bytes())
	if err != nil {
		return err
	}
	b, err := buffer.ExtendHeader(4)
	if err != nil {
		return err
	}
	hash.Sum(b[:0])
	return common.Error(w.upstream.Write(buffer.Bytes()))
}

func (w *StreamChecksumWriter) FrontHeadroom() int {
	return 4
}

func (w *StreamChecksumWriter) Upstream() any {
	return w.upstream
}
