// Package ping is a simple but powerful ICMP echo (ping) library.
//
// Here is a very simple example that sends and receives three packets:
//
//	PingClient, err := ping.NewPingClient("www.google.com")
//	if err != nil {
//		panic(err)
//	}
//	PingClient.Count = 3
//	err = PingClient.Run() // blocks until finished
//	if err != nil {
//		panic(err)
//	}
//	stats := PingClient.Statistics() // get send/receive/rtt stats
//
// Here is an example that emulates the traditional UNIX ping command:
//
//	PingClient, err := ping.NewPingClient("www.google.com")
//	if err != nil {
//		panic(err)
//	}
//	// Listen for Ctrl-C.
//	c := make(chan os.Signal, 1)
//	signal.Notify(c, os.Interrupt)
//	go func() {
//		for _ = range c {
//			PingClient.Stop()
//		}
//	}()
//	PingClient.OnRecv = func(pkt *ping.Packet) {
//		fmt.Printf("%d bytes from %s: icmp_seq=%d time=%v\n",
//			pkt.Nbytes, pkt.IPAddr, pkt.Seq, pkt.Rtt)
//	}
//	PingClient.OnFinish = func(stats *ping.Statistics) {
//		fmt.Printf("\n--- %s ping statistics ---\n", stats.Addr)
//		fmt.Printf("%d packets transmitted, %d packets received, %v%% packet loss\n",
//			stats.PacketsSent, stats.PacketsRecv, stats.PacketLoss)
//		fmt.Printf("round-trip min/avg/max/stddev = %v/%v/%v/%v\n",
//			stats.MinRtt, stats.AvgRtt, stats.MaxRtt, stats.StdDevRtt)
//	}
//	fmt.Printf("PING %s (%s):\n", PingClient.Addr(), PingClient.IPAddr())
//	err = PingClient.Run()
//	if err != nil {
//		panic(err)
//	}
//
// It sends ICMP Echo Request packet(s) and waits for an Echo Reply in response.
// If it receives a response, it calls the OnRecv callback. When it's finished,
// it calls the OnFinish callback.
//
// For a full ping example, see "cmd/ping/ping.go".
//
package lib

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"net"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const (
	timeSliceLength  = 8
	trackerLength    = 8
	protocolICMP     = 1
	protocolIPv6ICMP = 58
)

var (
	ipv4Proto = map[string]string{"icmp": "ip4:icmp", "udp": "udp4"}
	ipv6Proto = map[string]string{"icmp": "ip6:ipv6-icmp", "udp": "udp6"}
)

// New returns a new PingClient struct pointer.
func New(addr string) *PingClient {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	return &PingClient{
		Count:      0,
		Interval:   time.Second,
		RecordRtts: true,
		Size:       timeSliceLength + trackerLength,
		Timeout:    time.Second * 5,
		Tracker:    r.Int63n(math.MaxInt64),
		addr:       addr,
		done:       make(chan bool),
		id:         r.Intn(math.MaxInt16),
		ipaddr:     nil,
		ipv4:       false,
		network:    "ip",
		protocol:   "udp",
	}
}

func NewWithParams(interval time.Duration, timeout time.Duration, ips []*net.IPAddr,
	urls []string, num int, ipToURL map[*net.IPAddr]string) *PingClient {

	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	return &PingClient{
		Count:       0,
		Num:         num,
		Interval:    interval,
		RecordRtts:  true,
		Size:        timeSliceLength + trackerLength,
		Timeout:     timeout,
		Tracker:     r.Int63n(math.MaxInt64),
		packetsSent: make(map[*net.IPAddr]int),
		packetsRecv: make(map[*net.IPAddr]int),
		rtt:         make(map[*net.IPAddr][]time.Duration),
		ips:         ips,
		urls:        urls,
		ipToURL:     ipToURL,
		addr:        "",
		done:        make(chan bool),
		id:          r.Intn(math.MaxInt16),
		ipaddr:      nil,
		ipv4:        false,
		network:     "ip",
		protocol:    "udp",
	}
}

// Use simply resolves xx declared but not used issue
// for debug
func Use(args ...interface{}) {
	for _, val := range args {
		_ = val
	}
}

// ParsePingClient parses PingClient config yaml file and returns instance of PingClient
func ParsePingClient(pingClientMap map[interface{}]interface{}) (*PingClient, error) {
	interval := time.Second
	timeout := 5 * time.Second
	ips := make([]*net.IPAddr, 0)
	urls := make([]string, 0)
	num := 5
	ipToURL := make(map[*net.IPAddr]string)
	privileged := false

	for key := range pingClientMap {
		k := key.(string)
		stringKey := key.(string)

		switch k = strings.ToLower(strings.TrimSpace(k)); k {
		case "interval":
			intervalInt := pingClientMap[stringKey].(int)
			interval = time.Duration(intervalInt) * time.Millisecond
		case "timeout":
			timeoutInt := pingClientMap[stringKey].(int)
			timeout = time.Duration(timeoutInt) * time.Millisecond
		case "ips":
			ipStr := pingClientMap[stringKey].(string)
			ipStrList := strings.Split(ipStr, " ")
			var ip net.IP
			for _, v := range ipStrList {
				if ip = parseIP(v); ip == nil {
					return nil, fmt.Errorf("Error ParsePingClient(): %s should be in IP format x.x.x.x", v)
				}
				ips = append(ips, &net.IPAddr{IP: ip})
			}
		case "urls":
			urlStr := pingClientMap[stringKey].(string)
			urlList := strings.Split(urlStr, " ")
			for _, url := range urlList {
				ipaddr, err := parseURL("ip", url)
				if err != nil {
					return nil, fmt.Errorf("Error ParsePingClient(): can not resolve the IP address of url %s", url)
				}
				ips = append(ips, ipaddr)
				// construct inverted map
				ipToURL[ipaddr] = url
			}
		case "num":
			n := pingClientMap[stringKey].(int)
			num = n
		case "privileged":
			p := pingClientMap[stringKey].(bool)
			privileged = p
		}
	}

	pingClient := NewWithParams(interval, timeout, ips, urls, num, ipToURL)
	pingClient.SetPrivileged(privileged)

	return pingClient, nil

}

// NewPingClient returns a new PingClient and resolves the address.
func NewPingClient(addr string) (*PingClient, error) {
	p := New(addr)
	return p, p.Resolve()
}

// PingClient represents a packet sender/receiver.
type PingClient struct {
	// Interval is the wait time between each packet send. Default is 1s.
	Interval time.Duration

	// Timeout specifies a timeout before ping exits, regardless of how many
	// packets have been received.
	Timeout time.Duration

	// Count tells PingClient to stop after sending (and receiving) Count echo
	// packets. If this option is not specified, PingClient will operate until
	// interrupted.
	Count int

	// number of packets send per ip(or url) address
	Num int

	// Debug runs in debug mode
	Debug bool

	// Number of packets sent
	PacketsSent int

	packetsSent map[*net.IPAddr]int

	packetsRecv map[*net.IPAddr]int

	rtt map[*net.IPAddr][]time.Duration

	// Number of packets received
	PacketsRecv int

	// If true, keep a record of rtts of all received packets.
	// Set to false to avoid memory bloat for long running pings.
	RecordRtts bool

	// rtts is all of the Rtts
	rtts []time.Duration

	// OnRecv is called when PingClient receives and processes a packet
	OnRecv func(*Packet)

	// OnFinish is called when PingClient exits
	OnFinish func(*Statistics)

	// Size of packet being sent
	Size int

	// Tracker: Used to uniquely identify packet when non-priviledged
	Tracker int64

	// Source is the source IP address
	Source string

	// stop chan bool
	done chan bool

	ipaddr *net.IPAddr
	addr   string
	// list of destination ping ips
	ips []*net.IPAddr

	// list of destination ping urls
	urls []string

	ipToURL map[*net.IPAddr]string

	// has Ipv4 in ips
	hasIPv4 bool
	// has Ipv6 in ips
	hasIPv6 bool

	ipv4     bool
	id       int
	sequence int
	// network is one of "ip", "ip4", or "ip6".
	network string
	// protocol is "icmp" or "udp".
	protocol string
}

type packet struct {
	bytes  []byte
	nbytes int
	ttl    int
}

// Packet represents a received and processed ICMP echo packet.
type Packet struct {
	// Rtt is the round-trip time it took to ping.
	Rtt time.Duration

	// IPAddr is the address of the host being pinged.
	IPAddr *net.IPAddr

	// Addr is the string address of the host being pinged.
	Addr string

	// NBytes is the number of bytes in the message.
	Nbytes int

	// Seq is the ICMP sequence number.
	Seq int

	// TTL is the Time To Live on the packet.
	Ttl int
}

// Statistics represent the stats of a currently running or finished
// PingClient operation.
type Statistics struct {
	// PacketsRecv is the number of packets received.
	PacketsRecv int

	// PacketsSent is the number of packets sent.
	PacketsSent int

	// PacketLoss is the percentage of packets lost.
	PacketLoss float64

	// IPAddr is the address of the host being pinged.
	IPAddr *net.IPAddr

	// Addr is the string address of the host being pinged.
	Addr string

	// Rtts is all of the round-trip times sent via this PingClient.
	Rtts []time.Duration

	// MinRtt is the minimum round-trip time sent via this PingClient.
	MinRtt time.Duration

	// MaxRtt is the maximum round-trip time sent via this PingClient.
	MaxRtt time.Duration

	// AvgRtt is the average round-trip time sent via this PingClient.
	AvgRtt time.Duration

	// StdDevRtt is the standard deviation of the round-trip times sent via
	// this PingClient.
	StdDevRtt time.Duration
}

// SetIPAddr sets the ip address of the target host.
func (p *PingClient) SetIPAddr(ipaddr *net.IPAddr) {
	p.ipv4 = isIPv4(ipaddr.IP)

	p.ipaddr = ipaddr
	p.addr = ipaddr.String()
}

// IPAddr returns the ip address of the target host.
func (p *PingClient) IPAddr() *net.IPAddr {
	return p.ipaddr
}

// Resolve does the DNS lookup for the PingClient address and sets IP protocol.
func (p *PingClient) Resolve() error {
	if len(p.addr) == 0 {
		return errors.New("addr cannot be empty")
	}
	ipaddr, err := net.ResolveIPAddr(p.network, p.addr)
	if err != nil {
		return err
	}

	p.ipv4 = isIPv4(ipaddr.IP)

	p.ipaddr = ipaddr

	return nil
}

// SetAddr resolves and sets the ip address of the target host, addr can be a
// DNS name like "www.google.com" or IP like "127.0.0.1".
func (p *PingClient) SetAddr(addr string) error {
	oldAddr := p.addr
	p.addr = addr
	err := p.Resolve()
	if err != nil {
		p.addr = oldAddr
		return err
	}
	return nil
}

// Addr returns the string ip address of the target host.
func (p *PingClient) Addr() string {
	return p.addr
}

// SetNetwork allows configuration of DNS resolution.
// * "ip" will automatically select IPv4 or IPv6.
// * "ip4" will select IPv4.
// * "ip6" will select IPv6.
func (p *PingClient) SetNetwork(n string) {
	switch n {
	case "ip4":
		p.network = "ip4"
	case "ip6":
		p.network = "ip6"
	default:
		p.network = "ip"
	}
}

// SetPrivileged sets the type of ping PingClient will send.
// false means PingClient will send an "unprivileged" UDP ping.
// true means PingClient will send a "privileged" raw ICMP ping.
// NOTE: setting to true requires that it be run with super-user privileges.
func (p *PingClient) SetPrivileged(privileged bool) {
	if privileged {
		p.protocol = "icmp"
	} else {
		p.protocol = "udp"
	}
}

// Privileged returns whether PingClient is running in privileged mode.
func (p *PingClient) Privileged() bool {
	return p.protocol == "icmp"
}

// Run runs the PingClient. This is a blocking function that will exit when it's
// done. If Count or Interval are not specified, it will run continuously until
// it is interrupted.
func (p *PingClient) Run() error {
	var conn, conn6 *icmp.PacketConn
	var err error
	p.ipVersionCheck()
	p.initPacketsConfig()

	if p.hasIPv4 {
		if conn, err = p.listen(ipv4Proto[p.protocol]); err != nil {
			return err
		}
		if err = conn.IPv4PacketConn().SetControlMessage(ipv4.FlagTTL, true); runtime.GOOS != "windows" && err != nil {
			return err
		}
		defer conn.Close()
	}

	if p.hasIPv6 {
		if conn6, err = p.listen(ipv6Proto[p.protocol]); err != nil {
			return err
		}
		if err = conn.IPv6PacketConn().SetControlMessage(ipv6.FlagHopLimit, true); runtime.GOOS != "windows" && err != nil {
			return err
		}
		defer conn6.Close()
	}

	defer p.finish()

	var wg sync.WaitGroup
	recv := make(chan *packet, 5)
	defer close(recv)
	if conn != nil {
		wg.Add(1)
		//nolint:errcheck
		go p.recvICMP(conn, recv, &wg)
	}

	if conn6 != nil {
		wg.Add(1)
		//nolint:errcheck
		go p.recvICMP(conn6, recv, &wg)
	}

	err = p.sendICMP(conn, conn6)
	if err != nil {
		return err
	}

	timeout := time.NewTicker(p.Timeout)
	defer timeout.Stop()
	interval := time.NewTicker(p.Interval)
	defer interval.Stop()

	for {
		select {
		case <-p.done:
			wg.Wait()
			return nil
		case <-timeout.C:
			close(p.done)
			wg.Wait()
			return nil
		case <-interval.C:
			if p.Count > 0 && p.PacketsSent >= p.Count {
				continue
			}
			err = p.sendICMP(conn, conn6)
			if err != nil {
				// FIXME: this logs as FATAL but continues
				fmt.Println("FATAL: ", err.Error())
			}
		case r := <-recv:
			err := p.processPacket(r)
			if err != nil {
				// FIXME: this logs as FATAL but continues
				fmt.Println("FATAL: ", err.Error())
			}
		}
		if p.Count > 0 && p.PacketsRecv >= p.Count {
			close(p.done)
			wg.Wait()
			return nil
		}
	}
}

func (p *PingClient) Stop() {
	close(p.done)
}

func (p *PingClient) finish() {
	handler := p.OnFinish
	if handler != nil {
		s := p.Statistics()
		handler(s)
	}
}

// Statistics returns the statistics of the PingClient. This can be run while the
// PingClient is running or after it is finished. OnFinish calls this function to
// get it's finished statistics.
func (p *PingClient) Statistics() *Statistics {
	loss := float64(p.PacketsSent-p.PacketsRecv) / float64(p.PacketsSent) * 100
	var min, max, total time.Duration
	if len(p.rtts) > 0 {
		min = p.rtts[0]
		max = p.rtts[0]
	}
	for _, rtt := range p.rtts {
		if rtt < min {
			min = rtt
		}
		if rtt > max {
			max = rtt
		}
		total += rtt
	}
	s := Statistics{
		PacketsSent: p.PacketsSent,
		PacketsRecv: p.PacketsRecv,
		PacketLoss:  loss,
		Rtts:        p.rtts,
		Addr:        p.addr,
		IPAddr:      p.ipaddr,
		MaxRtt:      max,
		MinRtt:      min,
	}
	if len(p.rtts) > 0 {
		s.AvgRtt = total / time.Duration(len(p.rtts))
		var sumsquares time.Duration
		for _, rtt := range p.rtts {
			sumsquares += (rtt - s.AvgRtt) * (rtt - s.AvgRtt)
		}
		s.StdDevRtt = time.Duration(math.Sqrt(
			float64(sumsquares / time.Duration(len(p.rtts)))))
	}
	return &s
}

func (p *PingClient) recvICMP(
	conn *icmp.PacketConn,
	recv chan<- *packet,
	wg *sync.WaitGroup,
) error {
	defer wg.Done()
	for {
		select {
		case <-p.done:
			return nil
		default:
			bytes := make([]byte, 512)
			if err := conn.SetReadDeadline(time.Now().Add(time.Millisecond * 100)); err != nil {
				return err
			}
			var n, ttl int
			var err error
			if conn.IPv4PacketConn() != nil {
				var cm *ipv4.ControlMessage
				n, cm, _, err = conn.IPv4PacketConn().ReadFrom(bytes)
				if cm != nil {
					ttl = cm.TTL
				}
			} else if conn.IPv6PacketConn() != nil {
				var cm *ipv6.ControlMessage
				n, cm, _, err = conn.IPv6PacketConn().ReadFrom(bytes)
				if cm != nil {
					ttl = cm.HopLimit
				}
			} else {
				return nil
			}

			if err != nil {
				if neterr, ok := err.(*net.OpError); ok {
					if neterr.Timeout() {
						// Read timeout
						continue
					} else {
						close(p.done)
						return err
					}
				}
			}

			select {
			case <-p.done:
				return nil
			case recv <- &packet{bytes: bytes, nbytes: n, ttl: ttl}:
			}
		}
	}
}

func (p *PingClient) processPacket(recv *packet) error {
	receivedAt := time.Now()
	var proto int
	if p.ipv4 {
		proto = protocolICMP
	} else {
		proto = protocolIPv6ICMP
	}

	var m *icmp.Message
	var err error
	if m, err = icmp.ParseMessage(proto, recv.bytes); err != nil {
		return fmt.Errorf("error parsing icmp message: %s", err.Error())
	}

	if m.Type != ipv4.ICMPTypeEchoReply && m.Type != ipv6.ICMPTypeEchoReply {
		// Not an echo reply, ignore it
		return nil
	}

	outPkt := &Packet{
		Nbytes: recv.nbytes,
		IPAddr: p.ipaddr,
		Addr:   p.addr,
		Ttl:    recv.ttl,
	}

	switch pkt := m.Body.(type) {
	case *icmp.Echo:
		// If we are priviledged, we can match icmp.ID
		if p.protocol == "icmp" {
			// Check if reply from same ID
			if pkt.ID != p.id {
				return nil
			}
		}

		if len(pkt.Data) < timeSliceLength+trackerLength {
			return fmt.Errorf("insufficient data received; got: %d %v",
				len(pkt.Data), pkt.Data)
		}

		tracker := bytesToInt(pkt.Data[timeSliceLength:])
		timestamp := bytesToTime(pkt.Data[:timeSliceLength])

		if tracker != p.Tracker {
			return nil
		}

		outPkt.Rtt = receivedAt.Sub(timestamp)
		outPkt.Seq = pkt.Seq
		p.PacketsRecv++
	default:
		// Very bad, not sure how this can happen
		return fmt.Errorf("invalid ICMP echo reply; type: '%T', '%v'", pkt, pkt)
	}

	if p.RecordRtts {
		p.rtts = append(p.rtts, outPkt.Rtt)
	}
	handler := p.OnRecv
	if handler != nil {
		handler(outPkt)
	}

	return nil
}

func (p *PingClient) sendICMP(conn, conn6 *icmp.PacketConn) error {
	p.id = rand.Intn(0xffff)
	p.sequence = rand.Intn(0xffff)
	wg := new(sync.WaitGroup)
	for key, addr := range p.ips {
		var cn *icmp.PacketConn
		var typ icmp.Type
		Use(key, cn)
		if isIPv4(addr.IP) {
			cn = conn
			typ = ipv4.ICMPTypeEcho
		} else if isIpv6(addr.IP) {
			cn = conn6
			typ = ipv6.ICMPTypeEchoRequest
		} else {
			continue
		}

		var dst net.Addr = addr
		if p.protocol == "udp" {
			dst = &net.UDPAddr{IP: addr.IP, Zone: addr.Zone}
		}

		t := append(timeToBytes(time.Now()), intToBytes(p.Tracker)...)
		if remainSize := p.Size - timeSliceLength - trackerLength; remainSize > 0 {
			t = append(t, bytes.Repeat([]byte{1}, remainSize)...)
		}

		body := &icmp.Echo{
			ID:   p.id,
			Seq:  p.sequence,
			Data: t,
		}

		msg := &icmp.Message{
			Type: typ,
			Code: 0,
			Body: body,
		}

		msgBytes, err := msg.Marshal(nil)
		if err != nil {
			return err
		}
		wg.Add(1)
		go func(conn *icmp.PacketConn, dst net.Addr, b []byte) {
			for {
				if _, err := conn.WriteTo(b, dst); err != nil {
					if neterr, ok := err.(*net.OpError); ok {
						if neterr.Err == syscall.ENOBUFS {
							continue
						}
					}
				}
				p.packetsSent[addr]++
				break
			}
			wg.Done()
		}(cn, dst, msgBytes)
	}
	wg.Wait()

	return nil
}

func (p *PingClient) listen(netProto string) (*icmp.PacketConn, error) {
	conn, err := icmp.ListenPacket(netProto, p.Source)
	if err != nil {
		close(p.done)
		return nil, err
	}
	return conn, nil
}

func (p *PingClient) initPacketsConfig() {
	for _, addr := range p.ips {
		p.packetsSent[addr] = 0
		p.packetsRecv[addr] = 0
		p.rtt[addr] = make([]time.Duration, 0)
	}
}

func bytesToTime(b []byte) time.Time {
	var nsec int64
	for i := uint8(0); i < 8; i++ {
		nsec += int64(b[i]) << ((7 - i) * 8)
	}
	return time.Unix(nsec/1000000000, nsec%1000000000)
}

/* * * * * * * * * * * * * * * * * * * * * * *
  _____ _____    _    _ _   _ _
 |_   _|  __ \  | |  | | | (_) |
   | | | |__) | | |  | | |_ _| |___
   | | |  ___/  | |  | | __| | / __|
  _| |_| |      | |__| | |_| | \__ \
 |_____|_|       \____/ \__|_|_|___/

* * * * * * * * * * * * * * * * * * * * * * */

func (p *PingClient) ipVersionCheck() {
	for _, ipAddr := range p.ips {
		if isIPv4(ipAddr.IP) {
			p.hasIPv4 = true
		} else if isIpv6(ipAddr.IP) {
			p.hasIPv6 = true
		}
	}
}

// parse an stirng s to net.IP
// returns nil if s is not a valid ip(v4 or v6) address
func parseIP(s string) net.IP {
	return net.ParseIP(s)
}

// get IP addr of given string address using DNS lookup
// e.g. getIP("github.com")
// return	[]IP(4-byte Ipv4 and 16-byte Ipv6, Ipv4 could also be 16-byte)
func parseURL(network string, url string) (*net.IPAddr, error) {
	ips, err := net.ResolveIPAddr(network, url)
	if err != nil {
		return nil, err
	}
	return ips, nil
}

func isIPv4(ip net.IP) bool {
	return len(ip.To4()) == net.IPv4len
}

func isIpv6(ip net.IP) bool {
	return len(ip.To16()) == net.IPv6len
}

func timeToBytes(t time.Time) []byte {
	nsec := t.UnixNano()
	b := make([]byte, 8)
	for i := uint8(0); i < 8; i++ {
		b[i] = byte((nsec >> ((7 - i) * 8)) & 0xff)
	}
	return b
}

func bytesToInt(b []byte) int64 {
	return int64(binary.BigEndian.Uint64(b))
}

func intToBytes(tracker int64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(tracker))
	return b
}
