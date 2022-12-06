// Copyright 2022 Intuitive Labs GmbH. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE_BSD.txt file in the root of the source
// tree.

package sipcallmon

import (
	"bytes"
	"net"

	"github.com/intuitivelabs/calltr"
)

// ConnKey is the key used for connections (contains 2 endpoint IPs and ports)
type ConnKey struct {
	port  [2]uint16
	ipLen uint8
	ip    [2][16]byte
}

// InitConnKey  initializes a ConnKey, making sure the ip:ports are ordered.
// InitConnKey(&key1, ip1, port1, ip2, port2, 4) &&
// InitConnKey(&key2, ip2, port2, ip1, port1, 4) will produce equivalent
//  key1 && key2 (key1 == key2) so that the key can be used in hash table to
// refer to the same connection.
// It returns the key index for IP1 & port1 (0 or 1), that has to be used to
// retrieve the corresponding IP or Port in the IP(i) and Port(i) functions.
func InitConnKey(c *ConnKey,
	ip1 [16]byte, port1 uint16,
	ip2 [16]byte, port2 uint16,
	iplen uint8) uint8 {
	idx := uint8(0)
	if EndPointCmp(ip1, port1, ip2, port2, iplen) > 0 {
		idx = 1
	}
	c.port[idx] = port1
	c.port[1-idx] = port2
	c.ip[idx] = ip1
	c.ip[1-idx] = ip2
	// make sure unused parts are 0 (debugging)
	for i := int(iplen); i < len(c.ip[0]); i++ {
		c.ip[0][i] = 0
		c.ip[1][i] = 0
	}
	c.ipLen = iplen
	return idx
}

func (k ConnKey) Eq(k2 ConnKey) bool {
	if (k.port[0] != k2.port[0]) || (k.port[1] != k2.port[1]) {
		return false
	}
	if k.ipLen != k2.ipLen {
		return false
	}
	if !bytes.Equal(k.ip[0][:k.ipLen], k2.ip[0][:k.ipLen]) {
		return false
	}
	return bytes.Equal(k.ip[1][:k.ipLen], k2.ip[1][:k.ipLen])
}

func (k ConnKey) IP0raw(idx int) [16]byte {
	return k.ip[idx]
}

func (k ConnKey) IP0(idx int) net.IP {
	b := k.IP0raw(idx)
	return net.IP(b[:k.ipLen])
}

func (k ConnKey) Port0(idx int) uint16 {
	return k.port[idx]
}

func (k ConnKey) Endpoint0(srcIdx int) calltr.NetInfo {
	var endPoint calltr.NetInfo
	endPoint.SetIP(k.IP0(srcIdx))
	endPoint.Port = k.Port0(srcIdx)
	return endPoint
}

func (k ConnKey) IPLen() int {
	return int(k.ipLen)
}

func (k ConnKey) IP1raw(srcIdx int) [16]byte {
	return k.ip[1-srcIdx]
}

func (k ConnKey) IP1(srcIdx int) net.IP {
	b := k.IP1raw(srcIdx)
	return net.IP(b[:k.ipLen])
}

func (k ConnKey) Port1(srcIdx int) uint16 {
	return k.port[1-srcIdx]
}

func (k ConnKey) Endpoint1(srcIdx int) calltr.NetInfo {
	var endPoint calltr.NetInfo
	endPoint.SetIP(k.IP1(srcIdx))
	endPoint.Port = k.Port1(srcIdx)
	return endPoint
}

// EndPointCmp compares two ip:port pairs. The result is arbitrary, but it
// is consistent (it does enforce an order relation).
// Returns -1 if ip1:port1 < ip2:port2, 0 if equal and 1 if greater.
func EndPointCmp(ip1 [16]byte, port1 uint16,
	ip2 [16]byte, port2 uint16,
	iplen uint8) int {

	if port1 != port2 {
		if port1 < port2 {
			return -1
		}
		return 1
	}
	return bytes.Compare(ip1[:iplen], ip2[:iplen])
}
