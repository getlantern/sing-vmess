//go:build !linux

package bufio

import (
	"syscall"

	N "github.com/getlantern/sing-vmess/network"
)

func splice(source syscall.RawConn, destination syscall.RawConn, readCounters []N.CountFunc, writeCounters []N.CountFunc) (handed bool, n int64, err error) {
	return
}
