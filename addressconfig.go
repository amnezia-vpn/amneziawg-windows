/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2021 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"bytes"
	"log"
	"net"
	"net/netip"
	"sort"

	"github.com/amnezia-vpn/amnezia-wg/tun"
	"golang.org/x/sys/windows"

	"github.com/amnezia-vpn/awg-windows/conf"
	"github.com/amnezia-vpn/awg-windows/tunnel/firewall"
	"github.com/amnezia-vpn/awg-windows/tunnel/winipcfg"
)

func cleanupAddressesOnDisconnectedInterfaces(family winipcfg.AddressFamily, addresses []netip.Prefix) {
	if len(addresses) == 0 {
		return
	}
	includedInAddresses := func(a net.IPNet) bool {
		// TODO: this makes the whole algorithm O(n^2). But we can't stick net.IPNet in a Go hashmap. Bummer!
		for _, addr := range addresses {
			ipNetAddr := prefixToIPNet(addr)
			ip := ipNetAddr.IP
			if ip4 := ip.To4(); ip4 != nil {
				ip = ip4
			}
			mA, _ := ipNetAddr.Mask.Size()
			mB, _ := a.Mask.Size()
			if bytes.Equal(ip, a.IP) && mA == mB {
				return true
			}
		}
		return false
	}
	interfaces, err := winipcfg.GetAdaptersAddresses(family, winipcfg.GAAFlagDefault)
	if err != nil {
		return
	}
	for _, iface := range interfaces {
		if iface.OperStatus == winipcfg.IfOperStatusUp {
			continue
		}
		for address := iface.FirstUnicastAddress; address != nil; address = address.Next {
			ip := address.Address.IP()
			ipnet := net.IPNet{IP: ip, Mask: net.CIDRMask(int(address.OnLinkPrefixLength), 8*len(ip))}
			if includedInAddresses(ipnet) {
				log.Printf("Cleaning up stale address %s from interface ‘%s’", ipnet.String(), iface.FriendlyName())
				addr, _ := netip.AddrFromSlice(ip)
				b := int(bits(ip))
				iface.LUID.DeleteIPAddress(netip.PrefixFrom(addr, b) )
			}
		}
	}
}
func bits(ip net.IP) uint8 {
	if ip.To4() != nil {
		return 32
	}
	return 128
}

func prefixBits(prefix netip.Prefix) uint8 {
	bits := uint8(32)
	if prefix.Addr().Is6() {
		bits = 128
	}
	return bits
}

func prefixToIP(prefix netip.Prefix) net.IP {
	s := prefix.Addr().AsSlice()
	return net.IP(s) 
}

func prefixToMask(prefix netip.Prefix) net.IPMask {
	return prefixToIPNet(prefix).Mask
}

func prefixToIPNet(prefix netip.Prefix) net.IPNet{
    ip := prefixToIP(prefix)
	return net.IPNet{
		IP: ip,
		Mask: net.CIDRMask(prefix.Bits(), int(bits(ip))),
	}
}

func maskPrefix(prefix netip.Prefix) netip.Prefix{
	ip := prefixToIP(prefix)
	b := int(bits(ip))
	mask := net.CIDRMask(int(prefix.Bits()), b)
	for i := 0; i < b/8; i++ {
		ip[i] &= mask[i]
	}
	addr, _ := netip.AddrFromSlice(ip)
	return netip.PrefixFrom(addr, b)
}

func configureInterface(family winipcfg.AddressFamily, conf *conf.Config, tun *tun.NativeTun) error {
	luid := winipcfg.LUID(tun.LUID())

	estimatedRouteCount := 0
	for _, peer := range conf.Peers {
		estimatedRouteCount += len(peer.AllowedIPs)
	}
	routes := make([]winipcfg.RouteData, 0, estimatedRouteCount)
	addresses := make([]netip.Prefix, len(conf.Interface.Addresses))
	var haveV4Address, haveV6Address bool
	for _, addr := range conf.Interface.Addresses {
		if prefixBits(addr) == 32 {
			haveV4Address = true
		} else if prefixBits(addr) == 128 {
			haveV6Address = true
		}
	}

	foundDefault4 := false
	foundDefault6 := false
	for _, peer := range conf.Peers {
		for _, allowedip := range peer.AllowedIPs {
			allowedip = maskPrefix(allowedip)
			pBits := prefixBits(allowedip)
			if (pBits == 32 && !haveV4Address) || (pBits == 128 && !haveV6Address) {
				continue
			}
			route := winipcfg.RouteData{
				Destination: allowedip,
				Metric:      0,
			}
			if pBits == 32 {
				if allowedip.Bits() == 0 {
					foundDefault4 = true
				}
				ipv4Zero, _ := netip.ParseAddr("0.0.0.0")
				route.NextHop = ipv4Zero
			} else if pBits == 128 {
				if allowedip.Bits() == 0 {
					foundDefault6 = true
				}
				ipv6Zero, _ := netip.ParseAddr("0000:0000:0000:0000:0000:0000:0000:0000")
				route.NextHop = ipv6Zero
			}
			routes = append(routes, route)
		}
	}

	err := luid.SetIPAddressesForFamily(family, addresses)
	if err == windows.ERROR_OBJECT_ALREADY_EXISTS {
		cleanupAddressesOnDisconnectedInterfaces(family, addresses)
		err = luid.SetIPAddressesForFamily(family, addresses)
	}
	if err != nil {
		return err
	}

	deduplicatedRoutes := make([]*winipcfg.RouteData, 0, len(routes))
	sort.Slice(routes, func(i, j int) bool {
		if routes[i].Metric != routes[j].Metric {
			return routes[i].Metric < routes[j].Metric
		}
		if c := routes[i].NextHop.Compare(routes[j].NextHop); c != 0 {
			return c < 0
		}
		if c := routes[i].Destination.Addr().Compare(routes[j].Destination.Addr()); c != 0 {
			return c < 0
		}
		if c := bytes.Compare(prefixToMask(routes[i].Destination), prefixToMask(routes[j].Destination)); c != 0 {
			return c < 0
		}
		return false
	})
	for i := 0; i < len(routes); i++ {
		if i > 0 && routes[i].Metric == routes[i-1].Metric &&
			(routes[i].NextHop.Compare(routes[i-1].NextHop) == 0) &&
			(routes[i].Destination.Addr().Compare(routes[i-1].Destination.Addr()) == 0) &&
			bytes.Equal(prefixToMask(routes[i].Destination), prefixToMask(routes[i-1].Destination)) {
			continue
		}
		deduplicatedRoutes = append(deduplicatedRoutes, &routes[i])
	}

	if !conf.Interface.TableOff {
		err = luid.SetRoutesForFamily(family, deduplicatedRoutes)
		if err != nil {
			return err
		}
	}

	ipif, err := luid.IPInterface(family)
	if err != nil {
		return err
	}
	if conf.Interface.MTU > 0 {
		ipif.NLMTU = uint32(conf.Interface.MTU)
		tun.ForceMTU(int(ipif.NLMTU))
	}
	if family == windows.AF_INET {
		if foundDefault4 {
			ipif.UseAutomaticMetric = false
			ipif.Metric = 0
		}
	} else if family == windows.AF_INET6 {
		if foundDefault6 {
			ipif.UseAutomaticMetric = false
			ipif.Metric = 0
		}
		ipif.DadTransmits = 0
		ipif.RouterDiscoveryBehavior = winipcfg.RouterDiscoveryDisabled
	}
	return ipif.Set()
}

func enableFirewall(conf *conf.Config, tun *tun.NativeTun) error {
	doNotRestrict := true
	if len(conf.Peers) == 1 && !conf.Interface.TableOff {
	nextallowedip:
		for _, allowedip := range conf.Peers[0].AllowedIPs {
			if allowedip.Bits() == 0 {
				for _, b := range prefixToIP(allowedip) {
					if b != 0 {
						continue nextallowedip
					}
				}
				doNotRestrict = false
				break
			}
		}
	}
	log.Println("Enabling firewall rules")
	return firewall.EnableFirewall(tun.LUID(), doNotRestrict, conf.Interface.DNS)
}
