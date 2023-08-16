// Copyright 2023 Intuitive Labs GmbH. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE_BSD.txt file in the root of the source
// tree.

// Implement gopacket SLL2 (linux cooked capture v2) support

package sipcallmon

import (
	"encoding/binary"
	"errors"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// LinuxSLL2Layer handles the linux cooked capture v2 encapsulation
// (appears in pcap files when capturing from the "any" interface with
// newer versions of libpcap/tcpdump)
// It implements the Layer, LinkLayer and DecodingLayer interfaces
// (see https://pkg.go.dev/github.com/google/gopacket#DecodingLayer)
type LinuxSLL2Layer struct {
	layers.BaseLayer
	ProtocolType layers.EthernetType
	Interface    uint32
	LLAddrType   uint16
	PacketType   uint8
	LLAddrLen    uint8
	LLAddr       []byte // Source
}

// LayerTypeLinuxSLL2 is the new added layer type based on LinuxSSL2Layer.
//
//	(Numbers < 1000 are reserved for the gopacket library, 1000-1999 should be
//	 used for common application-specific types and are very fast; any other
//	number would result in slower lookup)
var LayerTypeLinuxSLL2 = gopacket.RegisterLayerType(1276,
	gopacket.LayerTypeMetadata{
		Name:    "Linux SLL2",
		Decoder: gopacket.DecodeFunc(decodeLinuxSLL2)})

func (sll2 *LinuxSLL2Layer) DecodeFromBytes(
	data []byte,
	df gopacket.DecodeFeedback) error {
	// SLL2 header: always 20 bytes, variable length link level address
	if len(data) < 20 {
		return errors.New("Linux SLL2 layer  packet too small")
	}
	sll2.ProtocolType = layers.EthernetType(binary.BigEndian.Uint16(data[0:2]))
	sll2.Interface = binary.BigEndian.Uint32(data[4:8])
	sll2.LLAddrType = binary.BigEndian.Uint16(data[8:10])
	sll2.PacketType = data[10]
	sll2.LLAddrLen = data[11]

	if (sll2.LLAddrLen + 12) > 20 {
		return errors.New("Linux SLL2 layer invalid link lever address length")
	}
	sll2.LLAddr = data[12 : sll2.LLAddrLen+12]
	sll2.BaseLayer = layers.BaseLayer{data[:20], data[20:]}

	return nil
}

func (sll2 *LinuxSLL2Layer) CanDecode() gopacket.LayerClass {
	return LayerTypeLinuxSLL2
}

func (sll2 *LinuxSLL2Layer) LinkFlow() gopacket.Flow {
	return gopacket.NewFlow(layers.EndpointMAC, sll2.LLAddr, nil)
}

func (sll2 *LinuxSLL2Layer) NextLayerType() gopacket.LayerType {

	// TODO: handle PacketType - some forced layers for some
	//       radio or ipgre types

	// TODO: handle new SLL2 types

	return sll2.ProtocolType.LayerType()
}

func (sll2 *LinuxSLL2Layer) LayerType() gopacket.LayerType {
	return LayerTypeLinuxSLL2
}

// gopacket.DecodeFunc callback, needed by  gopacket.RegisterLayerType
func decodeLinuxSLL2(data []byte, p gopacket.PacketBuilder) error {
	sll2 := &LinuxSLL2Layer{}
	if err := sll2.DecodeFromBytes(data, p); err != nil {
		return err
	}
	p.AddLayer(sll2)
	p.SetLinkLayer(sll2)
	return p.NextDecoder(sll2.NextLayerType())
}
