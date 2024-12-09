package vmess

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"io"
	"runtime"
	"time"

	"github.com/getlantern/sing-vmess/buf"
	"github.com/getlantern/sing-vmess/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/gofrs/uuid/v5"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/sha3"
)

const (
	Version              = 1
	ReadChunkSize        = 16384
	WriteChunkSize       = 15000
	CacheDurationSeconds = 120
	MaxPaddingSize       = 64
	MaxFrontHeadroom     = 2 + CipherOverhead
	MaxRearHeadroom      = CipherOverhead*2 + MaxPaddingSize
)

const (
	SecurityTypeLegacy           = 1
	SecurityTypeAuto             = 2
	SecurityTypeAes128Gcm        = 3
	SecurityTypeChacha20Poly1305 = 4
	SecurityTypeNone             = 5
	SecurityTypeZero             = 6
)

const (
	CommandTCP = 1
	CommandUDP = 2
	CommandMux = 3
)

const (
	RequestOptionChunkStream         = 1
	RequestOptionConnectionReuse     = 2
	RequestOptionChunkMasking        = 4
	RequestOptionGlobalPadding       = 8
	RequestOptionAuthenticatedLength = 16
)

// nonce in java called iv

const (
	KDFSaltConstAuthIDEncryptionKey             = "AES Auth ID Encryption"
	KDFSaltConstAEADRespHeaderLenKey            = "AEAD Resp Header Len Key"
	KDFSaltConstAEADRespHeaderLenIV             = "AEAD Resp Header Len IV"
	KDFSaltConstAEADRespHeaderPayloadKey        = "AEAD Resp Header Key"
	KDFSaltConstAEADRespHeaderPayloadIV         = "AEAD Resp Header IV"
	KDFSaltConstVMessAEADKDF                    = "VMess AEAD KDF"
	KDFSaltConstVMessHeaderPayloadAEADKey       = "VMess Header AEAD Key"
	KDFSaltConstVMessHeaderPayloadAEADIV        = "VMess Header AEAD Nonce"
	KDFSaltConstVMessHeaderPayloadLengthAEADKey = "VMess Header AEAD Key_Length"
	KDFSaltConstVMessHeaderPayloadLengthAEADIV  = "VMess Header AEAD Nonce_Length"
)

const (
	CipherOverhead = 16
)

const (
	StatusNew       = 1
	StatusKeep      = 2
	StatusEnd       = 3
	StatusKeepAlive = 4
	OptionData      = 1
	OptionError     = 2
	NetworkTCP      = 1
	NetworkUDP      = 2
)

var MuxDestination = M.Socksaddr{
	Fqdn: "v1.mux.cool",
	Port: 666,
}

type TimeFunc = func() time.Time

var (
	ErrUnsupportedSecurityType = E.New("vmess: unsupported security type")
	ErrInvalidChecksum         = E.New("vmess: invalid chunk checksum")
)

var AddressSerializer = M.NewSerializer(
	M.AddressFamilyByte(0x01, M.AddressFamilyIPv4),
	M.AddressFamilyByte(0x03, M.AddressFamilyIPv6),
	M.AddressFamilyByte(0x02, M.AddressFamilyFqdn),
	M.PortThenAddress(),
)

func Key(user uuid.UUID) (key [16]byte, err error) {
	md5hash := md5.New()
	_, err = md5hash.Write(user[:])
	if err != nil {
		return
	}
	_, err = md5hash.Write([]byte("c48619fe-8f02-49e0-b9e9-edf763e17e21"))
	if err != nil {
		return
	}
	md5hash.Sum(key[:0])
	return
}

func AlterId(user *uuid.UUID) (*uuid.UUID, error) {
	md5hash := md5.New()
	_, err := md5hash.Write(user[:])
	if err != nil {
		return nil, err
	}
	_, err = md5hash.Write([]byte("16167dc8-16b6-4e6d-b8bb-65dd68113a81"))
	if err != nil {
		return nil, err
	}
	var newUser *uuid.UUID
	for {
		md5hash.Sum(newUser[:0])
		if user != newUser {
			return newUser, nil
		}
		_, err = md5hash.Write([]byte("533eff8a-4113-4b10-b5ce-0f5d76b98cd2"))
		if err != nil {
			return nil, err
		}
	}
}

func AuthID(key [16]byte, time time.Time, buffer *buf.Buffer) error {
	err := binary.Write(buffer, binary.BigEndian, time.Unix())
	if err != nil {
		return err
	}
	buffer.WriteRandom(4)
	err = binary.Write(buffer, binary.BigEndian, crc32.ChecksumIEEE(buffer.Bytes()))
	if err != nil {
		return err
	}
	aesBlock, err := aes.NewCipher(KDF(key[:], KDFSaltConstAuthIDEncryptionKey)[:16])
	if err != nil {
		return err
	}
	aesBlock.Encrypt(buffer.Bytes(), buffer.Bytes())
	return nil
}

func AutoSecurityType() byte {
	if runtime.GOARCH == "amd64" || runtime.GOARCH == "s390x" || runtime.GOARCH == "arm64" {
		return SecurityTypeAes128Gcm
	}
	return SecurityTypeChacha20Poly1305
}

func GenerateChacha20Poly1305Key(b []byte) []byte {
	key := make([]byte, 32)
	checksum := md5.Sum(b)
	copy(key, checksum[:])
	checksum = md5.Sum(key[:16])
	copy(key[16:], checksum[:])
	return key
}

func CreateReader(upstream io.Reader, streamReader io.Reader, requestKey []byte, requestNonce []byte, key []byte, nonce []byte, security byte, option byte) (io.Reader, error) {
	var err error
	switch security {
	case SecurityTypeNone:
		var reader io.Reader
		if option&RequestOptionChunkStream != 0 {
			var globalPadding sha3.ShakeHash
			if option&RequestOptionGlobalPadding != 0 {
				globalPadding = sha3.NewShake128()
				_, err := globalPadding.Write(nonce)
				if err != nil {
					return nil, err
				}
			}
			if option&RequestOptionAuthenticatedLength != 0 {
				reader, err = NewAes128GcmChunkReader(upstream, requestKey, requestNonce, globalPadding)
			} else {
				var chunkMasking sha3.ShakeHash
				if option&RequestOptionChunkMasking != 0 {
					if globalPadding != nil {
						chunkMasking = globalPadding
					} else {
						chunkMasking = sha3.NewShake128()
						_, err := chunkMasking.Write(nonce)
						if err != nil {
							return nil, err
						}
					}
				}
				reader = NewStreamChunkReader(upstream, chunkMasking, globalPadding)
			}
		}
		if reader != nil {
			return reader, err
		} else {
			return upstream, err
		}
	case SecurityTypeLegacy:
		if streamReader == nil {
			streamReader, err = NewStreamReader(upstream, key, nonce)
		}
		if option&RequestOptionChunkStream != 0 {
			var globalPadding sha3.ShakeHash
			if option&RequestOptionGlobalPadding != 0 {
				globalPadding = sha3.NewShake128()
				_, err := globalPadding.Write(nonce)
				if err != nil {
					return nil, err
				}
			}
			var chunkMasking sha3.ShakeHash
			if option&RequestOptionChunkMasking != 0 {
				if globalPadding != nil {
					chunkMasking = globalPadding
				} else {
					chunkMasking = sha3.NewShake128()
					_, err := chunkMasking.Write(nonce)
					if err != nil {
						return nil, err
					}
				}
			}
			return NewStreamChecksumReader(NewStreamChunkReader(streamReader, chunkMasking, globalPadding)), nil
		}
		return streamReader, err
	case SecurityTypeAes128Gcm:
		var chunkReader io.Reader
		var globalPadding sha3.ShakeHash
		if option&RequestOptionGlobalPadding != 0 {
			globalPadding = sha3.NewShake128()
			_, err := globalPadding.Write(nonce)
			if err != nil {
				return nil, err
			}
		}
		if option&RequestOptionAuthenticatedLength != 0 {
			var err error
			chunkReader, err = NewAes128GcmChunkReader(upstream, requestKey, requestNonce, globalPadding)
			if err != nil {
				return nil, err
			}
		} else {
			var chunkMasking sha3.ShakeHash
			if option&RequestOptionChunkMasking != 0 {
				if globalPadding != nil {
					chunkMasking = globalPadding
				} else {
					chunkMasking = sha3.NewShake128()
					_, err := chunkMasking.Write(nonce)
					if err != nil {
						return nil, err
					}
				}
			}
			chunkReader = NewStreamChunkReader(upstream, chunkMasking, globalPadding)
		}
		return NewAes128GcmReader(chunkReader, key, nonce)
	case SecurityTypeChacha20Poly1305:
		var chunkReader io.Reader
		var globalPadding sha3.ShakeHash
		if option&RequestOptionGlobalPadding != 0 {
			globalPadding = sha3.NewShake128()
			_, err := globalPadding.Write(nonce)
			if err != nil {
				return nil, err
			}
		}
		if option&RequestOptionAuthenticatedLength != 0 {
			var err error
			chunkReader, err = NewChacha20Poly1305ChunkReader(upstream, requestKey, requestNonce, globalPadding)
			if err != nil {
				return nil, err
			}
		} else {
			var chunkMasking sha3.ShakeHash
			if option&RequestOptionChunkMasking != 0 {
				if globalPadding != nil {
					chunkMasking = globalPadding
				} else {
					chunkMasking = sha3.NewShake128()
					_, err := chunkMasking.Write(nonce)
					if err != nil {
						return nil, err
					}
				}
			}
			chunkReader = NewStreamChunkReader(upstream, chunkMasking, globalPadding)
		}
		return NewChacha20Poly1305Reader(chunkReader, key, nonce)
	default:
		return nil, errors.New("unexpected security type")
	}
}

func CreateWriter(upstream io.Writer, streamWriter io.Writer, requestKey []byte, requestNonce []byte, key []byte, nonce []byte, security byte, option byte) (io.Writer, error) {
	switch security {
	case SecurityTypeNone:
		var writer io.Writer
		var err error
		if option&RequestOptionChunkStream != 0 {
			var globalPadding sha3.ShakeHash
			if option&RequestOptionGlobalPadding != 0 {
				globalPadding = sha3.NewShake128()
				_, err = globalPadding.Write(nonce)
				if err != nil {
					return nil, err
				}
			}
			if option&RequestOptionAuthenticatedLength != 0 {
				writer, err = NewAes128GcmChunkWriter(upstream, requestKey, requestNonce, globalPadding)
			} else {
				var chunkMasking sha3.ShakeHash
				if option&RequestOptionChunkMasking != 0 {
					if globalPadding != nil {
						chunkMasking = globalPadding
					} else {
						chunkMasking = sha3.NewShake128()
						_, err = chunkMasking.Write(nonce)
						if err != nil {
							return nil, err
						}
					}
				}
				writer = NewStreamChunkWriter(upstream, chunkMasking, globalPadding)
			}
		}
		if writer != nil {
			return writer, err
		} else {
			return upstream, err
		}
	case SecurityTypeLegacy:
		var err error
		if streamWriter == nil {
			streamWriter, err = NewStreamWriter(upstream, key, nonce)
			if err != nil {
				return nil, err
			}
		}
		if option&RequestOptionChunkStream != 0 {
			var globalPadding sha3.ShakeHash
			if option&RequestOptionGlobalPadding != 0 {
				globalPadding = sha3.NewShake128()
				_, err = globalPadding.Write(nonce)
				if err != nil {
					return nil, err
				}
			}
			var chunkMasking sha3.ShakeHash
			if option&RequestOptionChunkMasking != 0 {
				if globalPadding != nil {
					chunkMasking = globalPadding
				} else {
					chunkMasking = sha3.NewShake128()
					_, err = chunkMasking.Write(nonce)
					if err != nil {
						return nil, err
					}
				}
			}
			return bufio.NewChunkWriter(NewStreamChecksumWriter(NewStreamChunkWriter(streamWriter, chunkMasking, globalPadding)), WriteChunkSize), nil
		}
		return NewStreamWriter(upstream, key, nonce)
	case SecurityTypeAes128Gcm:
		var err error
		var writer io.Writer
		var globalPadding sha3.ShakeHash
		if option&RequestOptionGlobalPadding != 0 {
			globalPadding = sha3.NewShake128()
			_, err := globalPadding.Write(nonce)
			if err != nil {
				return nil, err
			}
		}
		if option&RequestOptionAuthenticatedLength != 0 {
			writer, err = NewAes128GcmChunkWriter(upstream, requestKey, requestNonce, globalPadding)
			if err != nil {
				return nil, err
			}
		} else {
			var chunkMasking sha3.ShakeHash
			if option&RequestOptionChunkMasking != 0 {
				if globalPadding != nil {
					chunkMasking = globalPadding
				} else {
					chunkMasking = sha3.NewShake128()
					_, err := chunkMasking.Write(nonce)
					if err != nil {
						return nil, err
					}
				}
			}
			writer = NewStreamChunkWriter(upstream, chunkMasking, globalPadding)
		}
		gcm, err := NewAes128GcmWriter(writer, key, nonce)
		if err != nil {
			return nil, err
		}
		return bufio.NewChunkWriter(gcm, WriteChunkSize), nil
	case SecurityTypeChacha20Poly1305:
		var chunkWriter io.Writer
		var err error
		var globalPadding sha3.ShakeHash
		if option&RequestOptionGlobalPadding != 0 {
			globalPadding = sha3.NewShake128()
			_, err := globalPadding.Write(nonce)
			if err != nil {
				return nil, err
			}
		}
		if option&RequestOptionAuthenticatedLength != 0 {
			chunkWriter, err = NewChacha20Poly1305ChunkWriter(upstream, requestKey, requestNonce, globalPadding)
			if err != nil {
				return nil, err
			}
		} else {
			var chunkMasking sha3.ShakeHash
			if option&RequestOptionChunkMasking != 0 {
				if globalPadding != nil {
					chunkMasking = globalPadding
				} else {
					chunkMasking = sha3.NewShake128()
					_, err := chunkMasking.Write(nonce)
					if err != nil {
						return nil, err
					}
				}
			}
			chunkWriter = NewStreamChunkWriter(upstream, chunkMasking, globalPadding)
		}
		chacha, err := NewChacha20Poly1305Writer(chunkWriter, key, nonce)
		if err != nil {
			return nil, err
		}
		return bufio.NewChunkWriter(chacha, WriteChunkSize), nil
	default:
		return nil, errors.New("unexpected security type")
	}
}

func newAesGcm(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	outCipher, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return outCipher, nil
}

func newAesStream(key []byte, iv []byte, stream func(block cipher.Block, iv []byte) cipher.Stream) (cipher.Stream, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return stream(block, iv), nil
}

func newChacha20Poly1305(key []byte) (cipher.AEAD, error) {
	outCipher, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	return outCipher, nil
}
