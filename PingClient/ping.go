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
//	stats := PingClient.Statistics() // get send/receive/rtts stats
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
//	PingClient.OnFinish = func(stats []*ping.Statistics) {
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
	"fmt"
	"math"
	"math/rand"
	"net"
	"runtime"
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
func New() *PingClient {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	return &PingClient{
		Count:       0,
		Num:         5,
		Interval:    time.Second,
		RecordRtts:  true,
		Size:        timeSliceLength + trackerLength,
		Timeout:     5 * time.Second,
		Tracker:     r.Int63n(math.MaxInt64),
		PacketsSent: make(map[string]int),
		PacketsRecv: make(map[string]int),
		PacketsInfo: make(map[string]*Packet),
		rtts:        make(map[string][]time.Duration),
		ips:         make([]*net.IPAddr, 0),
		urls:        make([]string, 0),
		ipToURL:     make(map[*net.IPAddr]string),
		continuous:  false,
		done:        make(chan bool),
		id:          r.Intn(math.MaxInt16),
		network:     "ip",
		protocol:    "udp",
	}
}

// NewPingClient returns a new PingClient struct pointer and resolves string addr
func NewPingClient(addr string) (*PingClient, error) {
	p := New()
	return p, p.Add(addr)
}

// NewPrivilegedPingClient returns a new raw socket PingClient struct pointer and resolves string addr
func NewPrivilegedPingClient(addr string) (*PingClient, error) {
	p := New()
	p.SetPrivileged(true)
	return p, p.Add(addr)
}

// InitWithConfig inits list of ping clients configured by the yaml file
func InitWithConfig(conf *Config) []*PingClient {
	pingClients := make([]*PingClient, 0)
	for _, v := range conf.PingClientsConf {
		pingClient := NewPingClientWithConfig(v)
		pingClients = append(pingClients, pingClient)
	}
	return pingClients
}

// NewPingClientWithConfig uses struct PingClientConfig to create a new PingClient
func NewPingClientWithConfig(conf *PingClientConfig) *PingClient {
	pingClient := New()

	pingClient.Interval = conf.Interval
	pingClient.Timeout = conf.Timeout
	pingClient.ips = conf.IPs
	pingClient.urls = conf.URLs
	pingClient.Num = conf.Num
	pingClient.ipToURL = conf.IPToURL
	pingClient.continuous = conf.Continuous

	pingClient.SetPrivileged(conf.Privileged)

	return pingClient
}

// Use simply resolves xx declared but not used issue
// for debug
func Use(args ...interface{}) {
	for _, val := range args {
		_ = val
	}
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
	PacketsSent map[string]int

	// Number of packets received
	PacketsRecv map[string]int

	// Received packets info for Statistics use
	PacketsInfo map[string]*Packet

	// Round trip time duration of all the packets
	rtts map[string][]time.Duration

	// If true, keep a record of rtts of all received packets.
	// Set to false to avoid memory bloat for long running pings.
	RecordRtts bool

	// OnRecv is called when PingClient receives and processes a packet
	OnRecv func(*Packet)

	// OnFinish is called when PingClient exits
	OnFinish func([]*Statistics)

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

	// whether run continuously(forever)
	continuous bool

	// has Ipv4 in ips
	hasIPv4 bool
	// has Ipv6 in ips
	hasIPv6 bool

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
	src    net.Addr
	ttl    int
}

// Packet represents a received and processed ICMP echo packet.
type Packet struct {
	// Rtt is the round-trip time it took to ping.
	Rtt time.Duration

	// IPAddr is the address of the host being pinged.
	IPAddr *net.IPAddr

	// IP address in string format e.g "142.250.71.78"
	IP string

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

	// IP address in string format e.g "142.250.71.78"
	IP string

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
// done.
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
	if p.continuous {
		timeout.Stop()
	} else {
		defer timeout.Stop()
	}
	interval := time.NewTicker(p.Interval)
	defer interval.Stop()

	for {
		select {
		case <-p.done:
			wg.Wait()
			return nil
		case <-interval.C:
			if !p.continuous && p.Num > 0 && All(p.PacketsSent, packetsSentFinished, p.Num) {
				close(p.done)
				wg.Wait()
				return nil
			}
			err = p.sendICMP(conn, conn6)
			if err != nil {
				// FIXME: this logs as FATAL but continues
				fmt.Println("FATAL: ", err.Error())
			}
		case <-timeout.C:
			close(p.done)
			wg.Wait()
			return nil
		case r := <-recv:
			err := p.processPacket(r)
			if err != nil {
				// FIXME: this logs as FATAL but continues
				fmt.Println("FATAL: ", err.Error())
			}
		}
	}
}

// Stop the ping client
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
			var src net.Addr
			var err error
			if conn.IPv4PacketConn() != nil {
				var cm *ipv4.ControlMessage
				n, cm, src, err = conn.IPv4PacketConn().ReadFrom(bytes)
				if cm != nil {
					ttl = cm.TTL
				}
			} else if conn.IPv6PacketConn() != nil {
				var cm *ipv6.ControlMessage
				n, cm, src, err = conn.IPv6PacketConn().ReadFrom(bytes)
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
						fmt.Println("close here?")
						close(p.done)
						return err
					}
				}
			}

			select {
			case <-p.done:
				return nil
			case recv <- &packet{bytes: bytes, nbytes: n, src: src, ttl: ttl}:
			}
		}
	}
}

func (p *PingClient) processPacket(recv *packet) error {
	receivedAt := time.Now()
	var ipStr string
	var err error

	if ipStr, err = resolveIPFromAddr(recv.src); err != nil {
		return err
	}

	var proto int
	if isIPv4(parseIP(ipStr)) {
		proto = protocolICMP
	} else if isIPv6(parseIP(ipStr)) {
		proto = protocolIPv6ICMP
	} else {
		return fmt.Errorf("error processPacket() checking icmp packet IP address: %s", ipStr)
	}

	var m *icmp.Message
	if m, err = icmp.ParseMessage(proto, recv.bytes); err != nil {
		return fmt.Errorf("error parsing icmp message: %s", err.Error())
	}

	if m.Type != ipv4.ICMPTypeEchoReply && m.Type != ipv6.ICMPTypeEchoReply {
		// Not an echo reply, ignore it
		return nil
	}

	outPkt := &Packet{
		Nbytes: recv.nbytes,
		IPAddr: p.findIPAddrbyString(ipStr),
		IP:     ipStr,
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
		p.PacketsRecv[ipStr]++
	default:
		// Very bad, not sure how this can happen
		return fmt.Errorf("invalid ICMP echo reply; type: '%T', '%v'", pkt, pkt)
	}

	if p.RecordRtts {
		p.rtts[ipStr] = append(p.rtts[ipStr], outPkt.Rtt)
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
	for _, addr := range p.ips {
		if !p.continuous && p.PacketsSent[addr.IP.String()] >= p.Num {
			continue
		}
		var cn *icmp.PacketConn
		var typ icmp.Type
		if isIPv4(addr.IP) {
			cn = conn
			typ = ipv4.ICMPTypeEcho
		} else if isIPv6(addr.IP) {
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

		var ipStr string
		if ipStr, err = resolveIPFromAddr(dst); err != nil {
			return err
		}

		wg.Add(1)
		go func(conn *icmp.PacketConn, dst net.Addr, ipStr string, b []byte) {
			for {
				if _, err := conn.WriteTo(b, dst); err != nil {
					if neterr, ok := err.(*net.OpError); ok {
						if neterr.Err == syscall.ENOBUFS {
							continue
						}
					}
				}
				break
			}
			p.PacketsSent[ipStr]++
			wg.Done()
		}(cn, dst, ipStr, msgBytes)
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
		p.PacketsSent[addr.IP.String()] = 0
		p.PacketsRecv[addr.IP.String()] = 0
		p.rtts[addr.IP.String()] = make([]time.Duration, 0)
	}
}

// All checks whether all the map entry satisfies the function f
func All(m map[string]int, f func(int, int) bool, num int) bool {
	for _, val := range m {
		if !f(val, num) {
			return false
		}
	}
	return true
}

func packetsSentFinished(sent int, num int) bool {
	return sent >= num
}

/* * * * * * * * * * * * * * * * * * * * * * *
   _____ _        _   _     _   _
  / ____| |      | | (_)   | | (_)
 | (___ | |_ __ _| |_ _ ___| |_ _  ___ ___
  \___ \| __/ _` | __| / __| __| |/ __/ __|
  ____) | || (_| | |_| \__ \ |_| | (__\__ \
 |_____/ \__\__,_|\__|_|___/\__|_|\___|___/

* * * * * * * * * * * * * * * * * * * * * * */

// Statistics returns the statistics of the whole PingClient.
// This can be run while the PingClient is running or after it is finished.
// OnFinish calls this function to get it's finished statistics.
func (p *PingClient) Statistics() []*Statistics {
	stats := make([]*Statistics, 0)
	for _, ipAddr := range p.ips {
		s := p.StatisticsPerIP(ipAddr)
		stats = append(stats, s)
	}

	return stats
}

// StatisticsPerIP returns the statistics of the Ping info to the given IP address.
func (p *PingClient) StatisticsPerIP(ipAddr *net.IPAddr) *Statistics {
	var ipStr string = ipAddr.IP.String()
	loss := float64(p.PacketsSent[ipStr]-p.PacketsRecv[ipStr]) / float64(p.PacketsSent[ipStr]) * 100
	var min, max, total time.Duration
	if len(p.rtts[ipStr]) > 0 {
		min = p.rtts[ipStr][0]
		max = p.rtts[ipStr][0]
	}
	for _, rt := range p.rtts[ipStr] {
		if rt < min {
			min = rt
		}
		if rt > max {
			max = rt
		}
		total += rt
	}
	s := Statistics{
		PacketsSent: p.PacketsSent[ipStr],
		PacketsRecv: p.PacketsRecv[ipStr],
		PacketLoss:  loss,
		Rtts:        p.rtts[ipStr],
		IPAddr:      ipAddr,
		IP:          ipStr,
		MaxRtt:      max,
		MinRtt:      min,
	}
	if len(p.rtts[ipStr]) > 0 {
		s.AvgRtt = total / time.Duration(len(p.rtts[ipStr]))
		var sumsquares time.Duration
		for _, rt := range p.rtts[ipStr] {
			sumsquares += (rt - s.AvgRtt) * (rt - s.AvgRtt)
		}
		s.StdDevRtt = time.Duration(math.Sqrt(
			float64(sumsquares / time.Duration(len(p.rtts[ipStr])))))
	}
	return &s
}

/* * * * * * * * * * * * * * * * * * * * * * *
  _____ _____    _    _ _   _ _
 |_   _|  __ \  | |  | | | (_) |
   | | | |__) | | |  | | |_ _| |___
   | | |  ___/  | |  | | __| | / __|
  _| |_| |      | |__| | |_| | \__ \
 |_____|_|       \____/ \__|_|_|___/

* * * * * * * * * * * * * * * * * * * * * * */
// Add parses addr(ip format or url format) to net.IP and
// adds net.IP to pingClient
func (p *PingClient) Add(addr string) error {
	if parseIP(addr) != nil {
		return p.AddIPAddr(addr)
	}
	return p.AddURLAddr(addr)
}

// AddIPAddr adds IP address to ping client
func (p *PingClient) AddIPAddr(addr string) error {
	ip := parseIP(addr)
	if isIPv4(ip) {
		p.ips = append(p.ips, &net.IPAddr{IP: ip})
	} else if isIPv6(ip) {
		p.ips = append(p.ips, &net.IPAddr{IP: ip})
	} else {
		return fmt.Errorf("error AddIPAddr() addr %s should be a valid IP address", addr)
	}
	return nil
}

// AddURLAddr resolves URL addr to IP address and adds IP address to ping client
func (p *PingClient) AddURLAddr(addr string) error {
	ipAddr, err := parseURL(p.network, addr)
	if err != nil {
		return err
	}
	p.ips = append(p.ips, ipAddr)
	p.ipToURL[ipAddr] = addr

	return nil
}

func (p *PingClient) ipVersionCheck() {
	for _, ipAddr := range p.ips {
		if isIPv4(ipAddr.IP) {
			p.hasIPv4 = true
		} else if isIPv6(ipAddr.IP) {
			p.hasIPv6 = true
		}
	}
}

func (p *PingClient) findIPAddrbyString(s string) *net.IPAddr {
	for _, ipAddr := range p.ips {
		if ipAddr.IP.String() == s {
			return ipAddr
		}
	}
	return nil
}

func resolveIPFromAddr(addr net.Addr) (string, error) {
	var ipStr string
	switch addr := addr.(type) {
	case *net.IPAddr:
		ipStr = addr.IP.String()
	case *net.UDPAddr:
		ipStr = addr.IP.String()
	default:
		return "", fmt.Errorf("error processPacket() parsing icmp packet IP address: %s", addr)
	}

	return ipStr, nil
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

func isIPv6(ip net.IP) bool {
	return len(ip.To16()) == net.IPv6len
}

func bytesToTime(b []byte) time.Time {
	var nsec int64
	for i := uint8(0); i < 8; i++ {
		nsec += int64(b[i]) << ((7 - i) * 8)
	}
	return time.Unix(nsec/1000000000, nsec%1000000000)
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
