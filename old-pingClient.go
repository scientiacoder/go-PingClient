package main

import (
	//"golang.org/x/net/icmp"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"golang.org/x/net/icmp"
)

var (
	ipv4Proto = map[string]string{"ip": "ip4:icmp", "udp": "udp4"}
	ipv6Proto = map[string]string{"ip": "ip6:ipv6-icmp", "udp": "udp6"}
)

// Context controls the state of PingClient to stop or done
type Context struct {
	stop chan bool
	done chan bool
	err  chan bool
}

func NewContext() *Context {
	return &Context{stop: make(chan bool), done: make(chan bool), err: make(chan bool)}
}

// PingClient sends/receives ICMP packets
type PingClient struct {
	addrs   map[string]*net.IPAddr // key is the string format of ip addr
	network string                 // "ip" or "udp" refer to ICMP endpoints network
	mut     *sync.Mutex            // mutex lock
	ctx     *Context               // controls stop or done
	source  string                 // address source for icmp.ListenPacket
	hasIpv4 bool                   // has ipv4 in addrs
	hasIpv6 bool                   // has ipv6 in addrs
	id      int                    // same id for icmp.Echo
	seq     int                    // same seq for icmp.Echo
	debug   bool                   // debug mode, print debug info to stdout
}

func NewPingClient() *PingClient {

	return &PingClient{
		addrs:   make(map[string]*net.IPAddr),
		network: "ip",
		mut:     &sync.Mutex{},
		ctx:     NewContext(),
		debug:   true,
	}
}

// Todo: add Ipv6 support
func (p *PingClient) run(once bool) {
	p.debugln("run(): Starting...")

	var conn *icmp.PacketConn
	if p.hasIpv4 {
		if p.debug {
			p.debugln("listen(): Ipv4 endpoint listening...")
		}
		conn = p.listen(ipv4Proto[p.network], p.source)
		if conn == nil {
			return
		}
		defer conn.Close()
	}

}

/*
func (p *PingClient) sendICMPpackets(conn *icmp.PacketConn) {
	var typ icmp.Type
	var bod icmp.MessageBody

	typ = ipv4.ICMPTypeEcho
	p.id = rand.Intn(0xffff) // 65535
	p.seq = rand.Intn(0xffff)

	for key, addr := range p.addrs {
		now := time.Now()
		// An Echo represents an ICMP echo request or reply message body.
		bod = &icmp.Echo{
			ID:   p.id,
			Seq:  p.seq,
			Data: timeToBytes(now),
		}

		// type echo code 0 no code
		IcmpMsg := &icmp.Message{
			Type: typ,
			Code: 0,
			Body: bod,
		}

	}
}
*/

// For non-privileged datagram-oriented ICMP endpoints
// Examples:
//	p.listen("udp4", "192.168.0.1") ListenPacket("udp4", "192.168.0.1")
//	ListenPacket("udp4", "0.0.0.0")
//	ListenPacket("udp6", "fe80::1%en0")
//	ListenPacket("udp6", "::")
//
// For privileged raw ICMP endpoints, network must be "ip4" or "ip6"
// followed by a colon and an ICMP protocol number or name.
//
// Examples:
//	ListenPacket("ip4:icmp", "192.168.0.1")
func (p *PingClient) listen(netProto string, source string) *icmp.PacketConn {
	conn, err := icmp.ListenPacket(netProto, source)
	if err != nil {
		p.mut.Lock()
		defer p.mut.Unlock()
		if p.debug {
			p.debugln("listen(): error")
		}
		p.ctx.err <- true

		return nil
	}

	return conn
}

// addIP adds string like ip address "192.168.0.1" or "2404:6800:4006:803::2006"
// to PingClient
// Todo: check ipv6 zone support
func (p *PingClient) addIP(s string) error {
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
		p.hasIpv4 = true
	} else if isIpv6(ipaddr) {
		// Todo zone check(ipv6 may include zone %eth0)
		p.addrs[ipaddr.String()] = &net.IPAddr{
			IP: ipaddr,
		}
		p.hasIpv6 = true
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
func getIP(network string, url string) (*net.IPAddr, error) {
	ips, err := net.ResolveIPAddr(network, url)
	if err != nil {
		return nil, err
	}
	return ips, nil
}

// copy from fastping
// simply transfrom Time(underlying int64 timestamp) to byte array of length 8
func timeToBytes(t time.Time) []byte {
	nsec := t.UnixNano()
	b := make([]byte, 8)
	for i := uint8(0); i < 8; i++ {
		fmt.Println((nsec >> ((7 - i) * 8)))
		fmt.Println((nsec >> ((7 - i) * 8)) & 0xff)
		b[i] = byte((nsec >> ((7 - i) * 8)) & 0xff)
	}
	return b
}

func bytesToTime(b []byte) time.Time {
	var nsec int64
	for i := 0; i < 8; i++ {
		nsec += int64(b[i]) << ((7 - i) * 8)
	}
	return time.Unix(nsec/1000000000, nsec%1000000000)
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

	fmt.Println(net.ResolveIPAddr("ip", "googlecom"))
}
