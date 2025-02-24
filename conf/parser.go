/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2021 WireGuard LLC. All Rights Reserved.
 */

package conf

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"math"
	"net"
	"strconv"
	"strings"
	"time"

	"golang.org/x/text/encoding/unicode"

	"github.com/amnezia-vpn/amneziawg-windows/l18n"
)

type ParseError struct {
	why      string
	offender string
}

func (e *ParseError) Error() string {
	return l18n.Sprintf("%s: %q", e.why, e.offender)
}

func parseIPCidr(s string) (ipcidr *IPCidr, err error) {
	var addrStr, cidrStr string
	var cidr int

	i := strings.IndexByte(s, '/')
	if i < 0 {
		addrStr = s
	} else {
		addrStr, cidrStr = s[:i], s[i+1:]
	}

	err = &ParseError{l18n.Sprintf("Invalid IP address"), s}
	addr := net.ParseIP(addrStr)
	if addr == nil {
		return
	}
	maybeV4 := addr.To4()
	if maybeV4 != nil {
		addr = maybeV4
	}
	if len(cidrStr) > 0 {
		err = &ParseError{l18n.Sprintf("Invalid network prefix length"), s}
		cidr, err = strconv.Atoi(cidrStr)
		if err != nil || cidr < 0 || cidr > 128 {
			return
		}
		if cidr > 32 && maybeV4 != nil {
			return
		}
	} else {
		if maybeV4 != nil {
			cidr = 32
		} else {
			cidr = 128
		}
	}
	return &IPCidr{addr, uint8(cidr)}, nil
}

func parseEndpoint(s string) (*Endpoint, error) {
	i := strings.LastIndexByte(s, ':')
	if i < 0 {
		return nil, &ParseError{l18n.Sprintf("Missing port from endpoint"), s}
	}
	host, portStr := s[:i], s[i+1:]
	if len(host) < 1 {
		return nil, &ParseError{l18n.Sprintf("Invalid endpoint host"), host}
	}
	port, err := parsePort(portStr)
	if err != nil {
		return nil, err
	}
	hostColon := strings.IndexByte(host, ':')
	if host[0] == '[' || host[len(host)-1] == ']' || hostColon > 0 {
		err := &ParseError{l18n.Sprintf("Brackets must contain an IPv6 address"), host}
		if len(host) > 3 && host[0] == '[' && host[len(host)-1] == ']' && hostColon > 0 {
			end := len(host) - 1
			if i := strings.LastIndexByte(host, '%'); i > 1 {
				end = i
			}
			maybeV6 := net.ParseIP(host[1:end])
			if maybeV6 == nil || len(maybeV6) != net.IPv6len {
				return nil, err
			}
		} else {
			return nil, err
		}
		host = host[1 : len(host)-1]
	}
	return &Endpoint{host, uint16(port)}, nil
}

func parseMTU(s string) (uint16, error) {
	m, err := strconv.Atoi(s)
	if err != nil {
		return 0, err
	}
	if m < 576 || m > 65535 {
		return 0, &ParseError{l18n.Sprintf("Invalid MTU"), s}
	}
	return uint16(m), nil
}

func parsePort(s string) (uint16, error) {
	m, err := strconv.Atoi(s)
	if err != nil {
		return 0, err
	}
	if m < 0 || m > 65535 {
		return 0, &ParseError{l18n.Sprintf("Invalid port"), s}
	}
	return uint16(m), nil
}

func parseUint16(value, name string) (uint16, error) {
	m, err := strconv.Atoi(value)
	if err != nil {
		return 0, err
	}
	if m < 0 || m > math.MaxUint16 {
		return 0, &ParseError{l18n.Sprintf("Invalid %s", name), value}
	}
	return uint16(m), nil
}
func parseUint32(value, name string) (uint32, error) {
	m, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0, err
	}
	if m < 0 || m > math.MaxUint32 {
		return 0, &ParseError{l18n.Sprintf("Invalid %s", name), value}
	}
	return uint32(m), nil
}

func parsePersistentKeepalive(s string) (uint16, error) {
	if s == "off" {
		return 0, nil
	}
	m, err := strconv.Atoi(s)
	if err != nil {
		return 0, err
	}
	if m < 0 || m > 65535 {
		return 0, &ParseError{l18n.Sprintf("Invalid persistent keepalive"), s}
	}
	return uint16(m), nil
}

func parseTableOff(s string) (bool, error) {
	if s == "off" {
		return true, nil
	} else if s == "auto" || s == "main" {
		return false, nil
	}
	_, err := strconv.ParseUint(s, 10, 32)
	return false, err
}

func parseKeyBase64(s string) (*Key, error) {
	k, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, &ParseError{l18n.Sprintf("Invalid key: %v", err), s}
	}
	if len(k) != KeyLength {
		return nil, &ParseError{l18n.Sprintf("Keys must decode to exactly 32 bytes"), s}
	}
	var key Key
	copy(key[:], k)
	return &key, nil
}

func parseKeyHex(s string) (*Key, error) {
	k, err := hex.DecodeString(s)
	if err != nil {
		return nil, &ParseError{l18n.Sprintf("Invalid key: %v", err), s}
	}
	if len(k) != KeyLength {
		return nil, &ParseError{l18n.Sprintf("Keys must decode to exactly 32 bytes"), s}
	}
	var key Key
	copy(key[:], k)
	return &key, nil
}

func parseBytesOrStamp(s string) (uint64, error) {
	b, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, &ParseError{l18n.Sprintf("Number must be a number between 0 and 2^64-1: %v", err), s}
	}
	return b, nil
}

func splitList(s string) ([]string, error) {
	var out []string
	for _, split := range strings.Split(s, ",") {
		trim := strings.TrimSpace(split)
		if len(trim) == 0 {
			return nil, &ParseError{l18n.Sprintf("Two commas in a row"), s}
		}
		out = append(out, trim)
	}
	return out, nil
}

type parserState int

const (
	inInterfaceSection parserState = iota
	inPeerSection
	notInASection
)

func (c *Config) maybeAddPeer(p *Peer) {
	if p != nil {
		c.Peers = append(c.Peers, *p)
	}
}

func FromWgQuick(s string, name string) (*Config, error) {
	if !TunnelNameIsValid(name) {
		return nil, &ParseError{l18n.Sprintf("Tunnel name is not valid"), name}
	}
	lines := strings.Split(s, "\n")
	parserState := notInASection
	conf := Config{Name: name}
	sawPrivateKey := false
	conf.Interface.MTU = 1420
	var peer *Peer
	for _, line := range lines {
		pound := strings.IndexByte(line, '#')
		if pound >= 0 {
			line = line[:pound]
		}
		line = strings.TrimSpace(line)
		lineLower := strings.ToLower(line)
		if len(line) == 0 {
			continue
		}
		if lineLower == "[interface]" {
			conf.maybeAddPeer(peer)
			parserState = inInterfaceSection
			continue
		}
		if lineLower == "[peer]" {
			conf.maybeAddPeer(peer)
			peer = &Peer{}
			parserState = inPeerSection
			continue
		}
		if parserState == notInASection {
			return nil, &ParseError{l18n.Sprintf("Line must occur in a section"), line}
		}
		equals := strings.IndexByte(line, '=')
		if equals < 0 {
			return nil, &ParseError{l18n.Sprintf("Config key is missing an equals separator"), line}
		}
		key, val := strings.TrimSpace(lineLower[:equals]), strings.TrimSpace(line[equals+1:])
		if len(val) == 0 {
			return nil, &ParseError{l18n.Sprintf("Key must have a value"), line}
		}
		if parserState == inInterfaceSection {
			switch key {
			case "privatekey":
				k, err := parseKeyBase64(val)
				if err != nil {
					return nil, err
				}
				conf.Interface.PrivateKey = *k
				sawPrivateKey = true
			case "listenport":
				p, err := parsePort(val)
				if err != nil {
					return nil, err
				}
				conf.Interface.ListenPort = p
			case "jc":
				junkPacketCount, err := parseUint16(val, "junkPacketCount")
				if err != nil {
					return nil, err
				}
				conf.Interface.JunkPacketCount = junkPacketCount
			case "jmin":
				junkPacketMinSize, err := parseUint16(val, "junkPacketMinSize")
				if err != nil {
					return nil, err
				}
				conf.Interface.JunkPacketMinSize = junkPacketMinSize
			case "jmax":
				junkPacketMaxSize, err := parseUint16(val, "junkPacketMaxSize")
				if err != nil {
					return nil, err
				}
				conf.Interface.JunkPacketMaxSize = junkPacketMaxSize
			case "s1":
				initPacketJunkSize, err := parseUint16(
					val,
					"initPacketJunkSize",
				)
				if err != nil {
					return nil, err
				}
				conf.Interface.InitPacketJunkSize = initPacketJunkSize
			case "s2":
				responsePacketJunkSize, err := parseUint16(
					val,
					"responsePacketJunkSize",
				)
				if err != nil {
					return nil, err
				}
				conf.Interface.ResponsePacketJunkSize = responsePacketJunkSize
			case "h1":
				initPacketMagicHeader, err := parseUint32(val, "initPacketMagicHeader")
				if err != nil {
					return nil, err
				}
				conf.Interface.InitPacketMagicHeader = initPacketMagicHeader
			case "h2":
				responsePacketMagicHeader, err := parseUint32(val, "responsePacketMagicHeader")
				if err != nil {
					return nil, err
				}
				conf.Interface.ResponsePacketMagicHeader = responsePacketMagicHeader
			case "h3":
				underloadPacketMagicHeader, err := parseUint32(val, "underloadPacketMagicHeader")
				if err != nil {
					return nil, err
				}
				conf.Interface.UnderloadPacketMagicHeader = underloadPacketMagicHeader
			case "h4":
				transportPacketMagicHeader, err := parseUint32(val, "transportPacketMagicHeader")
				if err != nil {
					return nil, err
				}
				conf.Interface.TransportPacketMagicHeader = transportPacketMagicHeader
			case "luacodec":
				if len(val) == 0 {
					return nil, errors.New("Cannot parse empty luacodec")
				}
				luaCodec := val
				conf.Interface.LuaCodec = luaCodec
			case "mtu":
				m, err := parseMTU(val)
				if err != nil {
					return nil, err
				}
				conf.Interface.MTU = m
			case "address":
				addresses, err := splitList(val)
				if err != nil {
					return nil, err
				}
				for _, address := range addresses {
					a, err := parseIPCidr(address)
					if err != nil {
						return nil, err
					}
					conf.Interface.Addresses = append(conf.Interface.Addresses, *a)
				}
			case "dns":
				addresses, err := splitList(val)
				if err != nil {
					return nil, err
				}
				for _, address := range addresses {
					a := net.ParseIP(address)
					if a == nil {
						conf.Interface.DNSSearch = append(conf.Interface.DNSSearch, address)
					} else {
						conf.Interface.DNS = append(conf.Interface.DNS, a)
					}
				}
			case "preup":
				conf.Interface.PreUp = val
			case "postup":
				conf.Interface.PostUp = val
			case "predown":
				conf.Interface.PreDown = val
			case "postdown":
				conf.Interface.PostDown = val
			case "table":
				tableOff, err := parseTableOff(val)
				if err != nil {
					return nil, err
				}
				conf.Interface.TableOff = tableOff
			default:
				return nil, &ParseError{l18n.Sprintf("Invalid key for [Interface] section"), key}
			}
		} else if parserState == inPeerSection {
			switch key {
			case "publickey":
				k, err := parseKeyBase64(val)
				if err != nil {
					return nil, err
				}
				peer.PublicKey = *k
			case "presharedkey":
				k, err := parseKeyBase64(val)
				if err != nil {
					return nil, err
				}
				peer.PresharedKey = *k
			case "allowedips":
				addresses, err := splitList(val)
				if err != nil {
					return nil, err
				}
				for _, address := range addresses {
					a, err := parseIPCidr(address)
					if err != nil {
						return nil, err
					}
					peer.AllowedIPs = append(peer.AllowedIPs, *a)
				}
			case "persistentkeepalive":
				p, err := parsePersistentKeepalive(val)
				if err != nil {
					return nil, err
				}
				peer.PersistentKeepalive = p
			case "endpoint":
				e, err := parseEndpoint(val)
				if err != nil {
					return nil, err
				}
				peer.Endpoint = *e
			default:
				return nil, &ParseError{l18n.Sprintf("Invalid key for [Peer] section"), key}
			}
		}
	}
	conf.maybeAddPeer(peer)

	if !sawPrivateKey {
		return nil, &ParseError{l18n.Sprintf("An interface must have a private key"), l18n.Sprintf("[none specified]")}
	}
	for _, p := range conf.Peers {
		if p.PublicKey.IsZero() {
			return nil, &ParseError{l18n.Sprintf("All peers must have public keys"), l18n.Sprintf("[none specified]")}
		}
	}

	return &conf, nil
}

func FromWgQuickWithUnknownEncoding(s string, name string) (*Config, error) {
	c, firstErr := FromWgQuick(s, name)
	if firstErr == nil {
		return c, nil
	}
	for _, encoding := range unicode.All {
		decoded, err := encoding.NewDecoder().String(s)
		if err == nil {
			c, err := FromWgQuick(decoded, name)
			if err == nil {
				return c, nil
			}
		}
	}
	return nil, firstErr
}

func FromUAPI(reader io.Reader, existingConfig *Config) (*Config, error) {
	parserState := inInterfaceSection
	conf := Config{
		Name: existingConfig.Name,
		Interface: Interface{
			Addresses:                  existingConfig.Interface.Addresses,
			DNS:                        existingConfig.Interface.DNS,
			DNSSearch:                  existingConfig.Interface.DNSSearch,
			MTU:                        existingConfig.Interface.MTU,
			PreUp:                      existingConfig.Interface.PreUp,
			PostUp:                     existingConfig.Interface.PostUp,
			PreDown:                    existingConfig.Interface.PreDown,
			PostDown:                   existingConfig.Interface.PostDown,
			TableOff:                   existingConfig.Interface.TableOff,
			JunkPacketCount:            existingConfig.Interface.JunkPacketCount,
			JunkPacketMinSize:          existingConfig.Interface.JunkPacketMinSize,
			JunkPacketMaxSize:          existingConfig.Interface.JunkPacketMaxSize,
			InitPacketJunkSize:         existingConfig.Interface.InitPacketJunkSize,
			ResponsePacketJunkSize:     existingConfig.Interface.ResponsePacketJunkSize,
			InitPacketMagicHeader:      existingConfig.Interface.InitPacketMagicHeader,
			ResponsePacketMagicHeader:  existingConfig.Interface.ResponsePacketMagicHeader,
			UnderloadPacketMagicHeader: existingConfig.Interface.UnderloadPacketMagicHeader,
			TransportPacketMagicHeader: existingConfig.Interface.TransportPacketMagicHeader,
			LuaCodec:					existingConfig.Interface.LuaCodec,
		},
	}
	var peer *Peer
	lineReader := bufio.NewReader(reader)
	for {
		line, err := lineReader.ReadString('\n')
		if err != nil {
			return nil, err
		}
		line = line[:len(line)-1]
		if len(line) == 0 {
			break
		}
		equals := strings.IndexByte(line, '=')
		if equals < 0 {
			return nil, &ParseError{l18n.Sprintf("Config key is missing an equals separator"), line}
		}
		key, val := line[:equals], line[equals+1:]
		if len(val) == 0 {
			return nil, &ParseError{l18n.Sprintf("Key must have a value"), line}
		}
		switch key {
		case "public_key":
			conf.maybeAddPeer(peer)
			peer = &Peer{}
			parserState = inPeerSection
		case "errno":
			if val == "0" {
				continue
			} else {
				return nil, &ParseError{l18n.Sprintf("Error in getting configuration"), val}
			}
		}
		if parserState == inInterfaceSection {
			switch key {
			case "private_key":
				k, err := parseKeyHex(val)
				if err != nil {
					return nil, err
				}
				conf.Interface.PrivateKey = *k
			case "listen_port":
				p, err := parsePort(val)
				if err != nil {
					return nil, err
				}
				conf.Interface.ListenPort = p
			case "jc":
				junkPacketCount, err := parseUint16(val, "junkPacketCount")
				if err != nil {
					return nil, err
				}
				conf.Interface.JunkPacketCount = junkPacketCount
			case "jmin":
				junkPacketMinSize, err := parseUint16(val, "junkPacketMinSize")
				if err != nil {
					return nil, err
				}
				conf.Interface.JunkPacketMinSize = junkPacketMinSize
			case "jmax":
				junkPacketMaxSize, err := parseUint16(val, "junkPacketMaxSize")
				if err != nil {
					return nil, err
				}
				conf.Interface.JunkPacketMaxSize = junkPacketMaxSize
			case "s1":
				initPacketJunkSize, err := parseUint16(
					val,
					"initPacketJunkSize",
				)
				if err != nil {
					return nil, err
				}
				conf.Interface.InitPacketJunkSize = initPacketJunkSize
			case "s2":
				responsePacketJunkSize, err := parseUint16(
					val,
					"responsePacketJunkSize",
				)
				if err != nil {
					return nil, err
				}
				conf.Interface.ResponsePacketJunkSize = responsePacketJunkSize
			case "h1":
				initPacketMagicHeader, err := parseUint32(val, "initPacketMagicHeader")
				if err != nil {
					return nil, err
				}
				conf.Interface.InitPacketMagicHeader = initPacketMagicHeader
			case "h2":
				responsePacketMagicHeader, err := parseUint32(val, "responsePacketMagicHeader")
				if err != nil {
					return nil, err
				}
				conf.Interface.ResponsePacketMagicHeader = responsePacketMagicHeader
			case "h3":
				underloadPacketMagicHeader, err := parseUint32(val, "underloadPacketMagicHeader")
				if err != nil {
					return nil, err
				}
				conf.Interface.UnderloadPacketMagicHeader = underloadPacketMagicHeader
			case "h4":
				transportPacketMagicHeader, err := parseUint32(val, "transportPacketMagicHeader")
				if err != nil {
					return nil, err
				}
				conf.Interface.TransportPacketMagicHeader = transportPacketMagicHeader
			case "lua_codec":
				if len(val) == 0 {
					return nil, errors.New("Cannot parse empty lua_codec")
				}
				luaCodec := val
				conf.Interface.LuaCodec = luaCodec
			case "fwmark":
				// Ignored for now.

			default:
				return nil, &ParseError{l18n.Sprintf("Invalid key for interface section"), key}
			}
		} else if parserState == inPeerSection {
			switch key {
			case "public_key":
				k, err := parseKeyHex(val)
				if err != nil {
					return nil, err
				}
				peer.PublicKey = *k
			case "preshared_key":
				k, err := parseKeyHex(val)
				if err != nil {
					return nil, err
				}
				peer.PresharedKey = *k
			case "protocol_version":
				if val != "1" {
					return nil, &ParseError{l18n.Sprintf("Protocol version must be 1"), val}
				}
			case "allowed_ip":
				a, err := parseIPCidr(val)
				if err != nil {
					return nil, err
				}
				peer.AllowedIPs = append(peer.AllowedIPs, *a)
			case "persistent_keepalive_interval":
				p, err := parsePersistentKeepalive(val)
				if err != nil {
					return nil, err
				}
				peer.PersistentKeepalive = p
			case "endpoint":
				e, err := parseEndpoint(val)
				if err != nil {
					return nil, err
				}
				peer.Endpoint = *e
			case "tx_bytes":
				b, err := parseBytesOrStamp(val)
				if err != nil {
					return nil, err
				}
				peer.TxBytes = Bytes(b)
			case "rx_bytes":
				b, err := parseBytesOrStamp(val)
				if err != nil {
					return nil, err
				}
				peer.RxBytes = Bytes(b)
			case "last_handshake_time_sec":
				t, err := parseBytesOrStamp(val)
				if err != nil {
					return nil, err
				}
				peer.LastHandshakeTime += HandshakeTime(time.Duration(t) * time.Second)
			case "last_handshake_time_nsec":
				t, err := parseBytesOrStamp(val)
				if err != nil {
					return nil, err
				}
				peer.LastHandshakeTime += HandshakeTime(time.Duration(t) * time.Nanosecond)
			default:
				return nil, &ParseError{l18n.Sprintf("Invalid key for peer section"), key}
			}
		}
	}
	conf.maybeAddPeer(peer)

	return &conf, nil
}
