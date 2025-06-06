package testutils

import (
	"fmt"
	"net"
	"sync"
)

var (
	reserved     = []uint16{}
	reservedLock = sync.Mutex{}
)

func reserve(port uint16) bool {
	reservedLock.Lock()
	defer reservedLock.Unlock()

	for _, p := range reserved {
		if p == port {
			// reserved
			return false
		}
	}
	reserved = append(reserved, port)

	return true
}

// / FreePort returns a free port in the range [from, to).
// / It returns an error if no free port is found.
func FreePort(protocol string, from, to uint16) (uint16, error) {
	for port := from; port < to; port++ {
		if reserve(port) && IsPortFree(protocol, port) {
			return port, nil
		}
	}
	return 0, fmt.Errorf("no free %s port in range [%d, %d)", protocol, from, to)
}

// / IsPortFree returns true if the given port is free.
func IsPortFree(protocol string, port uint16) bool {
	addr := fmt.Sprintf(":%d", port)
	l, err := net.Listen(protocol, addr)
	if err != nil {
		return false
	}
	_ = l.Close()
	return true
}
