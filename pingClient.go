package main

import (
	//"golang.org/x/net/icmp"
	"fmt"
	"log"
	"net"
	"reflect"
	"sync"

	"golang.org/x/net/icmp"
)

var (
	ipv4Proto = map[string]string{"ip": "ip4:icmp", "udp": "udp4"}
	ipv6Proto = map[string]string{"ip": "ip6:ipv6-icmp", "udp": "udp6"}
)

// context controls the state of PingClient to stop or done
type context struct {
	stop chan bool
	done chan bool
	err  chan bool
}

// PingClient sends/receives ICMP packets
type PingClient struct {
	addrs   map[string]*net.IPAddr // key is the string format of ip addr
	network string                 // "ip" or "udp" refer to ICMP endpoints network
	mut     *sync.Mutex            // mutex lock
	ctx     *context               // controls stop or done
	source  string                 // address source for icmp.ListenPacket
	debug   bool                   // debug mode, print debug info to stdout
}

func NewPingClient() *PingClient {

	return &PingClient{
		addrs:   make(map[string]*net.IPAddr),
		network: "ip",
		mut:     &sync.Mutex{},
		ctx:     &context{stop: make(chan bool), done: make(chan bool), err: make(chan bool)},
		debug:   true,
	}
}

func (p *PingClient) run(once bool) {
	p.debugln("run(): Starting")
	p.listen(ipv4Proto[p.network], p.source)
}

func (p *PingClient) listen(netProto string, source string) *icmp.PacketConn {
	conn, err := icmp.ListenPacket(netProto, source)
	if err != nil {

	}

	return conn
}

// AddIP adds string like ip address "192.168.0.1" or "2404:6800:4006:803::2006"
// to PingClient
// Todo: check ipv6 zone support
func (p *PingClient) AddIP(s string) error {
	p.mut.Lock()
	defer p.mut.Unlock()
	ipaddr := parseIP(s)
	if ipaddr == nil {
		return fmt.Errorf("%s should be a valid IP address e.g 192.168.0.1 or 2404:6800:4006:803::2006", ipaddr)
	}

	if isIpv4(ipaddr) {
		p.addrs[ipaddr.String()] = &net.IPAddr{
			IP: ipaddr,
		}
	} else if isIpv6(ipaddr) {
		// Todo zone check(ipv6 may include zone %eth0)
		p.addrs[ipaddr.String()] = &net.IPAddr{
			IP: ipaddr,
		}
	}
	return nil
}

// RemoveIP deletes ip string from PingClient
func (p *PingClient) RemoveIP(s string) error {
	p.mut.Lock()
	defer p.mut.Unlock()
	delete(p.addrs, s)

	return nil
}

// get IP addr of given string address using DNS lookup
// e.g. getIP("github.com")
// return	[]IP(4-byte Ipv4 and 16-byte Ipv6, Ipv4 could also be 16-byte)
func getIP(s string) ([]net.IP, error) {
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
	return ips, err
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

func (p *PingClient) debugln(args ...interface{}) {
	p.mut.Lock()
	defer p.mut.Unlock()
	if p.debug {
		log.Println(args)
	}
}

/*
 * utils may delete later
 *
 */
var p = fmt.Println

func main() {
	getIP("github.com")
	iprecords, _ := net.LookupIP("mojotv.cn")
	for _, ip := range iprecords {
		fmt.Println(ip)
	}

	fmt.Println("-----")
	ip6 := parseIP("2404:6800:4006:803::2006")
	p(ip6.String())
	ip7 := parseIP("2001:db8:a0b:12f0::1%25eth0")
	p(ip7.String())

	m := make(map[string]string)
	m["a"] = "a"
	p(m["a"])
	delete(m, "a")
	delete(m, "b")
	p(m["a"])
}
