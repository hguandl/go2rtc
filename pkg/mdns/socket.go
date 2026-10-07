//go:build !darwin && !ios

package mdns

import (
	"context"
	"net"
	"syscall"
)

func listenMulticastSender(ctx context.Context, ip net.IP) (net.PacketConn, error) {
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				_ = SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
			})
		},
	}
	return lc.ListenPacket(ctx, "udp4", ip.String()+":5353") // same port important
}
