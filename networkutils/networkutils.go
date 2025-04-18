/*
Copyright 2022 The AlaudaDevops Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Ref: https://github.com/openshift/library-go/blob/d679fe6f824818b04acb36524917c7362de6b81e/pkg/network/networkutils/networkutils.go

package networkutils

import (
	"fmt"
	"net"
)

var localHosts []string = []string{"127.0.0.1", "::1", "localhost"}
var localSubnets []string = []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7", "fe80::/10"}

// IsPrivateAddress returns true if given address in format "<host>[:<port>]" is a localhost or an ip from
// private network range (e.g. 172.30.0.1, 192.168.0.1).
func IsPrivateAddress(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		// assume indexName is of the form `host` without the port and go on.
		host = addr
	}
	for _, localHost := range localHosts {
		if host == localHost {
			return true
		}
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}

	for _, subnet := range localSubnets {
		ipnet, err := ParseCIDRMask(subnet)
		if err != nil {
			continue // should not happen
		}
		if ipnet.Contains(ip) {
			return true
		}
	}
	return false
}

// ParseCIDRMask parses a CIDR string and ensures that it has no bits set beyond the
// network mask length. Use this when the input is supposed to be either a description of
// a subnet (eg, "192.168.1.0/24", meaning "192.168.1.0 to 192.168.1.255"), or a mask for
// matching against (eg, "192.168.1.15/32", meaning "must match all 32 bits of the address
// "192.168.1.15"). Use net.ParseCIDR() when the input is a host address that also
// describes the subnet that it is on (eg, "192.168.1.15/24", meaning "the address
// 192.168.1.15 on the network 192.168.1.0/24").
func ParseCIDRMask(cidr string) (*net.IPNet, error) {
	ip, net, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	if !ip.Equal(net.IP) {
		maskLen, addrLen := net.Mask.Size()
		return nil, fmt.Errorf("CIDR network specification %q is not in canonical form (should be %s/%d or %s/%d?)", cidr, ip.Mask(net.Mask).String(), maskLen, ip.String(), addrLen)
	}
	return net, nil
}
