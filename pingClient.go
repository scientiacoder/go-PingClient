package main

import (
	//"golang.org/x/net/icmp"
	"fmt"
	"net"
	"reflect"
)

var (
	ipv4Proto = map[string]string{"ip": "ip4:icmp", "udp": "udp4"}
	ipv6Proto = map[string]string{"ip": "ip6:ipv6-icmp", "udp": "udp6"}
)

type pingClient struct {
	addrs   map[string]*net.IP // key is the string format of ip addr
	network string             // "ip" or "udp" refer to ICMP endpoints network
}

// get IP addr of given string address using DNS lookup
// e.g. getIP("github.com")
// return	[]IP(4-byte Ipv4 and 16-byte Ipv6, Ipv4 could also be 16-byte)
func getIP(s string) {
	ips, err := net.LookupIP(s)
	if err == nil {
		fmt.Println(len(ips))
		for k, ip := range ips {
			fmt.Println(k, ip)
			fmt.Printf("%t %d\n", ip, len(ip))
			fmt.Println(ip.To4())
			fmt.Println(reflect.TypeOf(ip))
			fmt.Println(isIpv4(ip))
			fmt.Println(isIpv6(ip))
			fmt.Println(ip.String())

		}
	}
}

// Ipv4 check since Ipv4 could also be 16-byte
func isIpv4(ip net.IP) bool {
	return len(ip.To4()) == net.IPv4len
}

// Ipv6 check
func isIpv6(ip net.IP) bool {
	return len(ip.To16()) == net.IPv6len
}

// parse an stirng s to net.IP
// returns nil if s is not a valid ip(v4 or v6) address
func parseIP(s string) net.IP {
	return net.ParseIP(s)
}

func main() {
	getIP("github.com")
	iprecords, _ := net.LookupIP("mojotv.cn")
	for _, ip := range iprecords {
		fmt.Println(ip)
	}

	fmt.Println("-----")
}
