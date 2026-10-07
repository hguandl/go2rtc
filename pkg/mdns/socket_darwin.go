//go:build darwin || ios

package mdns

import (
	"context"
	"net"
	"syscall"
)

func listenMulticastSender(ctx context.Context, ip net.IP) (net.PacketConn, error) {
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var optErr error
			err := c.Control(func(fd uintptr) {
				// The BSD wrapper enables both SO_REUSEADDR and SO_REUSEPORT.
				optErr = SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
				if optErr == nil {
					optErr = syscall.SetsockoptInet4Addr(int(fd), syscall.IPPROTO_IP,
						syscall.IP_MULTICAST_IF, [4]byte(ip.To4()))
				}
			})
			if err != nil {
				return err
			}
			return optErr
		},
	}
	// Share the wildcard binding with mDNSResponder, selecting the multicast
	// interface explicitly rather than binding to its unicast address.
	return lc.ListenPacket(ctx, "udp4", ":5353")
}
