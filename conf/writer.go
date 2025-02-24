/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2021 WireGuard LLC. All Rights Reserved.
 */

package conf

import (
	"fmt"
	"strings"
)

func (conf *Config) ToWgQuick() string {
	var output strings.Builder
	output.WriteString("[Interface]\n")

	output.WriteString(fmt.Sprintf("PrivateKey = %s\n", conf.Interface.PrivateKey.String()))

	if conf.Interface.ListenPort > 0 {
		output.WriteString(fmt.Sprintf("ListenPort = %d\n", conf.Interface.ListenPort))
	}

	if conf.Interface.JunkPacketCount > 0 {
		output.WriteString(fmt.Sprintf("Jc = %d\n", conf.Interface.JunkPacketCount))
	}

	if conf.Interface.JunkPacketMinSize > 0 {
		output.WriteString(fmt.Sprintf("Jmin = %d\n", conf.Interface.JunkPacketMinSize))
	}

	if conf.Interface.JunkPacketMaxSize > 0 {
		output.WriteString(fmt.Sprintf("Jmax = %d\n", conf.Interface.JunkPacketMaxSize))
	}

	if conf.Interface.InitPacketJunkSize > 0 {
		output.WriteString(fmt.Sprintf("S1 = %d\n", conf.Interface.InitPacketJunkSize))
	}

	if conf.Interface.ResponsePacketJunkSize > 0 {
		output.WriteString(fmt.Sprintf("S2 = %d\n", conf.Interface.ResponsePacketJunkSize))
	}

	if conf.Interface.InitPacketMagicHeader > 0 {
		output.WriteString(fmt.Sprintf("H1 = %d\n", conf.Interface.InitPacketMagicHeader))
	}

	if conf.Interface.ResponsePacketMagicHeader > 0 {
		output.WriteString(fmt.Sprintf("H2 = %d\n", conf.Interface.ResponsePacketMagicHeader))
	}

	if conf.Interface.UnderloadPacketMagicHeader > 0 {
		output.WriteString(fmt.Sprintf("H3 = %d\n", conf.Interface.UnderloadPacketMagicHeader))
	}

	if conf.Interface.TransportPacketMagicHeader > 0 {
		output.WriteString(fmt.Sprintf("H4 = %d\n", conf.Interface.TransportPacketMagicHeader))
	}

	if conf.Interface.LuaCodec != "" {
		output.WriteString(fmt.Sprintf("LuaCodec = %s\n", conf.Interface.LuaCodec))
	}

	if len(conf.Interface.Addresses) > 0 {
		addrStrings := make([]string, len(conf.Interface.Addresses))
		for i, address := range conf.Interface.Addresses {
			addrStrings[i] = address.String()
		}
		output.WriteString(fmt.Sprintf("Address = %s\n", strings.Join(addrStrings[:], ", ")))
	}

	if len(conf.Interface.DNS)+len(conf.Interface.DNSSearch) > 0 {
		addrStrings := make([]string, 0, len(conf.Interface.DNS)+len(conf.Interface.DNSSearch))
		for _, address := range conf.Interface.DNS {
			addrStrings = append(addrStrings, address.String())
		}
		addrStrings = append(addrStrings, conf.Interface.DNSSearch...)
		output.WriteString(fmt.Sprintf("DNS = %s\n", strings.Join(addrStrings[:], ", ")))
	}

	if conf.Interface.MTU > 0 {
		output.WriteString(fmt.Sprintf("MTU = %d\n", conf.Interface.MTU))
	}

	if len(conf.Interface.PreUp) > 0 {
		output.WriteString(fmt.Sprintf("PreUp = %s\n", conf.Interface.PreUp))
	}
	if len(conf.Interface.PostUp) > 0 {
		output.WriteString(fmt.Sprintf("PostUp = %s\n", conf.Interface.PostUp))
	}
	if len(conf.Interface.PreDown) > 0 {
		output.WriteString(fmt.Sprintf("PreDown = %s\n", conf.Interface.PreDown))
	}
	if len(conf.Interface.PostDown) > 0 {
		output.WriteString(fmt.Sprintf("PostDown = %s\n", conf.Interface.PostDown))
	}
	if conf.Interface.TableOff {
		output.WriteString("Table = off\n")
	}

	for _, peer := range conf.Peers {
		output.WriteString("\n[Peer]\n")

		output.WriteString(fmt.Sprintf("PublicKey = %s\n", peer.PublicKey.String()))

		if !peer.PresharedKey.IsZero() {
			output.WriteString(fmt.Sprintf("PresharedKey = %s\n", peer.PresharedKey.String()))
		}

		if len(peer.AllowedIPs) > 0 {
			addrStrings := make([]string, len(peer.AllowedIPs))
			for i, address := range peer.AllowedIPs {
				addrStrings[i] = address.String()
			}
			output.WriteString(fmt.Sprintf("AllowedIPs = %s\n", strings.Join(addrStrings[:], ", ")))
		}

		if !peer.Endpoint.IsEmpty() {
			output.WriteString(fmt.Sprintf("Endpoint = %s\n", peer.Endpoint.String()))
		}

		if peer.PersistentKeepalive > 0 {
			output.WriteString(fmt.Sprintf("PersistentKeepalive = %d\n", peer.PersistentKeepalive))
		}
	}
	return output.String()
}

func (conf *Config) ToUAPI() (uapi string, dnsErr error) {
	var output strings.Builder
	output.WriteString(fmt.Sprintf("private_key=%s\n", conf.Interface.PrivateKey.HexString()))

	if conf.Interface.ListenPort > 0 {
		output.WriteString(fmt.Sprintf("listen_port=%d\n", conf.Interface.ListenPort))
	}

	if conf.Interface.LuaCodec != "" {
		output.WriteString(fmt.Sprintf("lua_codec=%s\n", conf.Interface.LuaCodec))
	}

	if conf.Interface.JunkPacketCount > 0 {
		output.WriteString(fmt.Sprintf("jc=%d\n", conf.Interface.JunkPacketCount))
	}

	if conf.Interface.JunkPacketMinSize > 0 {
		output.WriteString(fmt.Sprintf("jmin=%d\n", conf.Interface.JunkPacketMinSize))
	}

	if conf.Interface.JunkPacketMaxSize > 0 {
		output.WriteString(fmt.Sprintf("jmax=%d\n", conf.Interface.JunkPacketMaxSize))
	}

	if conf.Interface.InitPacketJunkSize > 0 {
		output.WriteString(fmt.Sprintf("s1=%d\n", conf.Interface.InitPacketJunkSize))
	}

	if conf.Interface.ResponsePacketJunkSize > 0 {
		output.WriteString(fmt.Sprintf("s2=%d\n", conf.Interface.ResponsePacketJunkSize))
	}

	if conf.Interface.InitPacketMagicHeader > 0 {
		output.WriteString(fmt.Sprintf("h1=%d\n", conf.Interface.InitPacketMagicHeader))
	}

	if conf.Interface.ResponsePacketMagicHeader > 0 {
		output.WriteString(fmt.Sprintf("h2=%d\n", conf.Interface.ResponsePacketMagicHeader))
	}

	if conf.Interface.UnderloadPacketMagicHeader > 0 {
		output.WriteString(fmt.Sprintf("h3=%d\n", conf.Interface.UnderloadPacketMagicHeader))
	}

	if conf.Interface.TransportPacketMagicHeader > 0 {
		output.WriteString(fmt.Sprintf("h4=%d\n", conf.Interface.TransportPacketMagicHeader))
	}

	if len(conf.Peers) > 0 {
		output.WriteString("replace_peers=true\n")
	}

	for _, peer := range conf.Peers {
		output.WriteString(fmt.Sprintf("public_key=%s\n", peer.PublicKey.HexString()))

		if !peer.PresharedKey.IsZero() {
			output.WriteString(fmt.Sprintf("preshared_key=%s\n", peer.PresharedKey.HexString()))
		}

		if !peer.Endpoint.IsEmpty() {
			var resolvedIP string
			resolvedIP, dnsErr = resolveHostname(peer.Endpoint.Host)
			if dnsErr != nil {
				return
			}
			resolvedEndpoint := Endpoint{resolvedIP, peer.Endpoint.Port}
			output.WriteString(fmt.Sprintf("endpoint=%s\n", resolvedEndpoint.String()))
		}

		output.WriteString(fmt.Sprintf("persistent_keepalive_interval=%d\n", peer.PersistentKeepalive))

		if len(peer.AllowedIPs) > 0 {
			output.WriteString("replace_allowed_ips=true\n")
			for _, address := range peer.AllowedIPs {
				output.WriteString(fmt.Sprintf("allowed_ip=%s\n", address.String()))
			}
		}
	}
	return output.String(), nil
}
