package urlvalidator

import (
	"context"
	"errors"
	"net"
	"time"
)

// DialPublic dials the vetted literal address without a second DNS lookup.
func DialPublic(ctx context.Context, network, address string, dial func(context.Context, string, string) (net.Conn, error)) (net.Conn, error) {
	return dialPublic(ctx, network, address, dial, net.DefaultResolver.LookupIPAddr)
}

func dialPublic(ctx context.Context, network, address string, dial func(context.Context, string, string) (net.Conn, error), lookup func(context.Context, string) ([]net.IPAddr, error)) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, errors.New("invalid outbound address")
	}
	ips, err := lookup(ctx, host)
	if err != nil || len(ips) == 0 {
		return nil, errors.New("outbound DNS resolution failed")
	}
	for _, entry := range ips {
		if !entry.IP.IsGlobalUnicast() || isBlockedHost(entry.IP.String()) {
			return nil, errors.New("outbound address is not public")
		}
	}
	for _, entry := range ips {
		if network == "tcp4" && entry.IP.To4() == nil {
			continue
		}
		if network == "tcp6" && entry.IP.To4() != nil {
			continue
		}
		conn, err := dial(ctx, network, net.JoinHostPort(entry.IP.String(), port))
		if err == nil {
			return conn, nil
		}
	}
	return nil, errors.New("outbound public connection failed")
}
