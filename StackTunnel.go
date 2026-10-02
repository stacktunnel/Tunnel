// Reverse TCP tunnel: kharej (client) dials Iran (server).
// First packet is an SSH-2.0 banner sent alone; afterwards everything is
// AEAD-encrypted and multiplexed with yamux.
//
//   Iran:   ./tunnel -mode server -key SECRET -tunnel :4000 -ports 443 -udp 51820 -pad 128
//   Kharej: ./tunnel -mode client -key SECRET -tunnel IRAN_IP:4000 -ports 443 -udp 51820 -pad 128 -conns 4
//
// Users connect to Iran:443 (tcp) / Iran:51820 (udp) -> through the tunnel ->
// kharej 127.0.0.1:443 / 127.0.0.1:51820.
// UDP datagrams are carried inside the same encrypted TCP tunnel (length-prefixed).
package main

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	mrand "math/rand"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/yamux"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	banner   = "SSH-2.0-OpenSSH_9.6\r\n"
	maxPlain = 16384
	overhead = 16

	protoTCP = 0
	protoUDP = 1

	udpIdle = 60 * time.Second
)

// max random padding bytes added to every encrypted frame (0 = off)
var padMax = 128

// address the user-facing ports bind to on the server ("" = all interfaces)
var bindAddr = ""

// ---------- preamble ----------

func readBanner(c net.Conn) error {
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	defer c.SetReadDeadline(time.Time{})
	line := make([]byte, 0, 64)
	b := make([]byte, 1)
	for len(line) < 255 {
		if _, err := io.ReadFull(c, b); err != nil {
			return err
		}
		line = append(line, b[0])
		if b[0] == '\n' {
			if strings.HasPrefix(string(line), "SSH-2.0-") {
				return nil
			}
			return errors.New("bad banner")
		}
	}
	return errors.New("banner too long")
}

func tune(c net.Conn) {
	if t, ok := c.(*net.TCPConn); ok {
		t.SetNoDelay(true)
		t.SetKeepAlive(true)
		t.SetKeepAlivePeriod(60 * time.Second)
	}
}

// ---------- encrypted conn ----------

type secConn struct {
	net.Conn
	wmu    sync.Mutex
	wa, ra cipher.AEAD
	wlk    []byte // key that masks the frame length (send)
	rlk    []byte // key that unmasks the frame length (receive)
	wn, rn uint64
	rbuf   []byte
}

func nonce(n uint64) []byte {
	b := make([]byte, 12)
	binary.LittleEndian.PutUint64(b[4:], n)
	return b
}

func derive(psk string, salt []byte) cipher.AEAD {
	h := sha256.New()
	h.Write([]byte("tunnel-v1"))
	h.Write([]byte(psk))
	h.Write(salt)
	a, _ := chacha20poly1305.New(h.Sum(nil))
	return a
}

func lenKey(psk string, salt []byte) []byte {
	h := sha256.New()
	h.Write([]byte("tunnel-len-v1"))
	h.Write([]byte(psk))
	h.Write(salt)
	return h.Sum(nil)
}

// lenMask is a keyed PRF output used to hide the 2-byte frame length.
func lenMask(key []byte, n uint64) uint16 {
	h := sha256.New()
	h.Write(key)
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], n)
	h.Write(b[:])
	return binary.BigEndian.Uint16(h.Sum(nil))
}

// ---------- fake SSH handshake ----------
//
// banner -> KEXINIT -> KEX_ECDH_INIT / KEX_ECDH_REPLY -> NEWKEYS
// All packets use the real SSH binary packet format. The "ephemeral key"
// field carries our random salt; after NEWKEYS everything is our own
// encrypted framing (which, like real SSH, looks like random bytes).

func sshString(b []byte, s string) []byte {
	n := len(s)
	b = append(b, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	return append(b, s...)
}

func parseSSHStrings(p []byte) ([][]byte, error) {
	var out [][]byte
	p = p[1:] // skip message code
	for len(p) > 0 {
		if len(p) < 4 {
			return nil, errors.New("short string header")
		}
		n := int(binary.BigEndian.Uint32(p))
		p = p[4:]
		if n < 0 || n > len(p) {
			return nil, errors.New("bad string length")
		}
		out = append(out, p[:n])
		p = p[n:]
	}
	return out, nil
}

func writeSSHPacket(w io.Writer, payload []byte) error {
	pad := 8 - ((5 + len(payload)) % 8)
	if pad < 4 {
		pad += 8
	}
	pkt := make([]byte, 5+len(payload)+pad)
	binary.BigEndian.PutUint32(pkt, uint32(1+len(payload)+pad))
	pkt[4] = byte(pad)
	copy(pkt[5:], payload)
	rand.Read(pkt[5+len(payload):])
	_, err := w.Write(pkt)
	return err
}

func readSSHPacket(r io.Reader) ([]byte, error) {
	var h [4]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return nil, err
	}
	l := int(binary.BigEndian.Uint32(h[:]))
	if l < 6 || l > 35000 {
		return nil, errors.New("bad ssh packet length")
	}
	b := make([]byte, l)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, err
	}
	pad := int(b[0])
	if pad+1 > l {
		return nil, errors.New("bad ssh padding")
	}
	return b[1 : l-pad], nil
}

func buildKexInit(client bool) []byte {
	p := []byte{20}
	cookie := make([]byte, 16)
	rand.Read(cookie)
	p = append(p, cookie...)
	kex := "sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org," +
		"ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256," +
		"diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256"
	if client {
		kex += ",ext-info-c,kex-strict-c-v00@openssh.com"
	} else {
		kex += ",ext-info-s,kex-strict-s-v00@openssh.com"
	}
	hostkeys := "ssh-ed25519-cert-v01@openssh.com,ecdsa-sha2-nistp256-cert-v01@openssh.com," +
		"rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com," +
		"ecdsa-sha2-nistp256,ssh-ed25519,rsa-sha2-512,rsa-sha2-256"
	enc := "chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com"
	mac := "umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com," +
		"hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com," +
		"umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1"
	comp := "none,zlib@openssh.com"
	for _, l := range []string{kex, hostkeys, enc, enc, mac, mac, comp, comp, "", ""} {
		p = sshString(p, l)
	}
	return append(p, 0, 0, 0, 0, 0) // first_kex_packet_follows + reserved
}

func sshBlob(alg string, n int) string {
	k := make([]byte, n)
	rand.Read(k)
	b := sshString(nil, alg)
	b = sshString(b, string(k))
	return string(b)
}

func handshake(c net.Conn, psk string, isClient bool) (*secConn, error) {
	c.SetDeadline(time.Now().Add(20 * time.Second))
	defer c.SetDeadline(time.Time{})

	my := make([]byte, 32) // first 16 bytes = salt, rest = filler
	rand.Read(my)
	expect := func(code byte) ([]byte, error) {
		p, err := readSSHPacket(c)
		if err != nil {
			return nil, err
		}
		if len(p) == 0 || p[0] != code {
			return nil, errors.New("unexpected handshake message")
		}
		return p, nil
	}
	newkeys := []byte{21}
	var peer []byte

	if isClient {
		// The banner goes out alone as the very first data segment.
		if _, err := c.Write([]byte(banner)); err != nil {
			return nil, err
		}
		if err := readBanner(c); err != nil {
			return nil, err
		}
		if err := writeSSHPacket(c, buildKexInit(true)); err != nil {
			return nil, err
		}
		if _, err := expect(20); err != nil {
			return nil, err
		}
		if err := writeSSHPacket(c, append([]byte{30}, sshString(nil, string(my))...)); err != nil {
			return nil, err
		}
		rep, err := expect(31)
		if err != nil {
			return nil, err
		}
		strs, err := parseSSHStrings(rep)
		if err != nil || len(strs) < 2 || len(strs[1]) != 32 {
			return nil, errors.New("bad ECDH reply")
		}
		peer = strs[1]
		if err := writeSSHPacket(c, newkeys); err != nil {
			return nil, err
		}
		if _, err := expect(21); err != nil {
			return nil, err
		}
	} else {
		if err := readBanner(c); err != nil {
			return nil, err
		}
		if _, err := c.Write([]byte(banner)); err != nil {
			return nil, err
		}
		if _, err := expect(20); err != nil {
			return nil, err
		}
		if err := writeSSHPacket(c, buildKexInit(false)); err != nil {
			return nil, err
		}
		in, err := expect(30)
		if err != nil {
			return nil, err
		}
		strs, err := parseSSHStrings(in)
		if err != nil || len(strs) < 1 || len(strs[0]) != 32 {
			return nil, errors.New("bad ECDH init")
		}
		peer = strs[0]
		reply := []byte{31}
		reply = sshString(reply, sshBlob("ssh-ed25519", 32))
		reply = sshString(reply, string(my))
		reply = sshString(reply, sshBlob("ssh-ed25519", 64))
		if err := writeSSHPacket(c, reply); err != nil {
			return nil, err
		}
		if _, err := expect(21); err != nil {
			return nil, err
		}
		if err := writeSSHPacket(c, newkeys); err != nil {
			return nil, err
		}
	}

	sendSalt, recvSalt := my[:16], peer[:16]
	return &secConn{
		Conn: c,
		wa:   derive(psk, sendSalt), ra: derive(psk, recvSalt),
		wlk: lenKey(psk, sendSalt), rlk: lenKey(psk, recvSalt),
	}, nil
}

func (s *secConn) Write(p []byte) (int, error) {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	total := 0
	for len(p) > 0 {
		n := len(p)
		if n > maxPlain {
			n = maxPlain
		}
		// plaintext = [2B real length][data][random-length zero padding]
		pad := 0
		if padMax > 0 {
			pad = mrand.Intn(padMax + 1)
			if n < 128 { // small frames (acks, headers) get extra variance
				pad += mrand.Intn(129)
			}
		}
		plain := make([]byte, 2+n+pad)
		binary.BigEndian.PutUint16(plain, uint16(n))
		copy(plain[2:], p[:n])
		var hdr [2]byte
		binary.BigEndian.PutUint16(hdr[:], uint16(len(plain)+overhead)^lenMask(s.wlk, s.wn))
		frame := make([]byte, 0, 2+len(plain)+overhead)
		frame = append(frame, hdr[:]...)
		frame = s.wa.Seal(frame, nonce(s.wn), plain, hdr[:])
		s.wn++
		if _, err := s.Conn.Write(frame); err != nil {
			return total, err
		}
		total += n
		p = p[n:]
	}
	return total, nil
}

func (s *secConn) Read(p []byte) (int, error) {
	for len(s.rbuf) == 0 {
		var hdr [2]byte
		if _, err := io.ReadFull(s.Conn, hdr[:]); err != nil {
			return 0, err
		}
		l := int(binary.BigEndian.Uint16(hdr[:]) ^ lenMask(s.rlk, s.rn))
		if l < overhead+2 || l > maxPlain+overhead+2+4096+256 {
			return 0, errors.New("bad frame length")
		}
		ct := make([]byte, l)
		if _, err := io.ReadFull(s.Conn, ct); err != nil {
			return 0, err
		}
		pt, err := s.ra.Open(ct[:0], nonce(s.rn), ct, hdr[:])
		if err != nil {
			return 0, errors.New("decrypt failed (wrong key?)")
		}
		s.rn++
		real := int(binary.BigEndian.Uint16(pt))
		if real > len(pt)-2 {
			return 0, errors.New("bad padding header")
		}
		s.rbuf = pt[2 : 2+real]
	}
	n := copy(p, s.rbuf)
	s.rbuf = s.rbuf[n:]
	return n, nil
}

// ---------- helpers ----------

func yamuxCfg() *yamux.Config {
	c := yamux.DefaultConfig()
	c.KeepAliveInterval = 15 * time.Second
	c.ConnectionWriteTimeout = 20 * time.Second
	c.MaxStreamWindowSize = 8 << 20
	c.LogOutput = io.Discard
	return c
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
	} else {
		c.Close() // yamux stream: Close() is a half-close (FIN)
	}
}

func pipe(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	cp := func(dst, src net.Conn) {
		defer wg.Done()
		io.Copy(dst, src)
		closeWrite(dst)
	}
	go cp(a, b)
	go cp(b, a)
	wg.Wait()
	a.Close()
	b.Close()
}

func parsePorts(s string) []int {
	var out []int
	if strings.TrimSpace(s) == "" {
		return nil
	}
	for _, f := range strings.Split(s, ",") {
		f = strings.TrimSpace(f)
		lo, hi := f, f
		if i := strings.Index(f, "-"); i > 0 { // range like 8000-8100
			lo, hi = f[:i], f[i+1:]
		}
		a, err1 := strconv.Atoi(lo)
		b, err2 := strconv.Atoi(hi)
		if err1 != nil || err2 != nil || a < 1 || b > 65535 || a > b || b-a > 2000 {
			log.Fatalf("bad port/range %q (ranges up to 2000 ports)", f)
		}
		for p := a; p <= b; p++ {
			out = append(out, p)
		}
	}
	return out
}

// ---------- server (Iran) ----------

// member = one tunnel connection plus the ports its kharej client serves.
type member struct {
	sess     *yamux.Session
	tcp, udp map[int]bool
}

type pool struct {
	mu sync.Mutex
	s  []*member
	i  int
}

func (p *pool) add(m *member) {
	p.mu.Lock()
	p.s = append(p.s, m)
	p.mu.Unlock()
}

func (p *pool) remove(m *member) {
	p.mu.Lock()
	for i, x := range p.s {
		if x == m {
			p.s = append(p.s[:i], p.s[i+1:]...)
			break
		}
	}
	p.mu.Unlock()
}

// pick returns a tunnel connection whose client serves this port
// (round-robin between all clients that announced it).
func (p *pool) pick(proto byte, port int) *yamux.Session {
	p.mu.Lock()
	defer p.mu.Unlock()
	var cand []*member
	for _, m := range p.s {
		set := m.tcp
		if proto == protoUDP {
			set = m.udp
		}
		if set[port] {
			cand = append(cand, m)
		}
	}
	if len(cand) == 0 {
		return nil
	}
	p.i++
	return cand[p.i%len(cand)].sess
}

// hello (client -> server, first stream): [2B n][n x 2B tcp ports][2B m][m x 2B udp ports]
func writeHello(w io.Writer, tcp, udp map[int]bool) error {
	var b []byte
	for _, set := range []map[int]bool{tcp, udp} {
		b = append(b, byte(len(set)>>8), byte(len(set)))
		for p := range set {
			b = append(b, byte(p>>8), byte(p))
		}
	}
	_, err := w.Write(b)
	return err
}

func readHello(r io.Reader) (tcp, udp map[int]bool, err error) {
	res := [2]map[int]bool{{}, {}}
	for i := range res {
		var h [2]byte
		if _, err = io.ReadFull(r, h[:]); err != nil {
			return
		}
		n := int(binary.BigEndian.Uint16(h[:]))
		buf := make([]byte, n*2)
		if _, err = io.ReadFull(r, buf); err != nil {
			return
		}
		for j := 0; j < n; j++ {
			res[i][int(binary.BigEndian.Uint16(buf[j*2:]))] = true
		}
	}
	return res[0], res[1], nil
}

func handleTunnel(c net.Conn, psk string, p *pool) {
	tune(c)
	sc, err := handshake(c, psk, false)
	if err != nil {
		c.Close()
		return
	}
	sess, err := yamux.Server(sc, yamuxCfg())
	if err != nil {
		c.Close()
		return
	}
	timer := time.AfterFunc(10*time.Second, func() { sess.Close() })
	hs, err := sess.Accept()
	if err != nil {
		sess.Close()
		return
	}
	tcp, udp, err := readHello(hs)
	hs.Close()
	timer.Stop()
	if err != nil {
		sess.Close()
		return
	}
	m := &member{sess: sess, tcp: tcp, udp: udp}
	p.add(m)
	log.Printf("tunnel up from %s: %d tcp / %d udp ports", c.RemoteAddr(), len(tcp), len(udp))
	<-sess.CloseChan()
	p.remove(m)
	log.Printf("tunnel down from %s", c.RemoteAddr())
}

func serveExposed(port int, p *pool) {
	l, err := net.Listen("tcp", fmt.Sprintf("%s:%d", bindAddr, port))
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("exposing :%d", port)
	for {
		c, err := l.Accept()
		if err != nil {
			continue
		}
		go func() {
			tune(c)
			sess := p.pick(protoTCP, port)
			if sess == nil {
				c.Close()
				return
			}
			st, err := sess.Open()
			if err != nil {
				c.Close()
				return
			}
			if _, err := st.Write(streamHdr(protoTCP, port)); err != nil {
				st.Close()
				c.Close()
				return
			}
			pipe(c, st)
		}()
	}
}

func streamHdr(proto byte, port int) []byte {
	return []byte{proto, byte(port >> 8), byte(port)}
}

// writeDgram sends one length-prefixed datagram on a stream (single Write).
func writeDgram(w io.Writer, d []byte) error {
	b := make([]byte, 2+len(d))
	binary.BigEndian.PutUint16(b, uint16(len(d)))
	copy(b[2:], d)
	_, err := w.Write(b)
	return err
}

func readDgram(r io.Reader, buf []byte) (int, error) {
	var h [2]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return 0, err
	}
	n := int(binary.BigEndian.Uint16(h[:]))
	if n > len(buf) {
		return 0, errors.New("datagram too large")
	}
	_, err := io.ReadFull(r, buf[:n])
	return n, err
}

type udpFlow struct {
	st   net.Conn
	last time.Time
}

func serveUDP(port int, p *pool) {
	pc, err := net.ListenPacket("udp", fmt.Sprintf("%s:%d", bindAddr, port))
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("exposing :%d/udp", port)
	var mu sync.Mutex
	flows := map[string]*udpFlow{}

	go func() { // idle reaper
		for range time.Tick(15 * time.Second) {
			mu.Lock()
			for k, f := range flows {
				if time.Since(f.last) > udpIdle {
					f.st.Close()
					delete(flows, k)
				}
			}
			mu.Unlock()
		}
	}()

	buf := make([]byte, 65535)
	for {
		n, src, err := pc.ReadFrom(buf)
		if err != nil {
			continue
		}
		key := src.String()
		mu.Lock()
		f := flows[key]
		if f == nil {
			sess := p.pick(protoUDP, port)
			if sess == nil {
				mu.Unlock()
				continue
			}
			st, err := sess.Open()
			if err != nil {
				mu.Unlock()
				continue
			}
			if _, err := st.Write(streamHdr(protoUDP, port)); err != nil {
				st.Close()
				mu.Unlock()
				continue
			}
			f = &udpFlow{st: st}
			flows[key] = f
			go func(src net.Addr, st net.Conn) { // tunnel -> user
				rb := make([]byte, 65535)
				for {
					n, err := readDgram(st, rb)
					if err != nil {
						break
					}
					mu.Lock()
					if fl := flows[src.String()]; fl != nil {
						fl.last = time.Now()
					}
					mu.Unlock()
					pc.WriteTo(rb[:n], src)
				}
				st.Close()
				mu.Lock()
				if fl := flows[src.String()]; fl != nil && fl.st == st {
					delete(flows, src.String())
				}
				mu.Unlock()
			}(src, st)
		}
		f.last = time.Now()
		st := f.st
		mu.Unlock()
		if err := writeDgram(st, buf[:n]); err != nil {
			st.Close()
		}
	}
}

func runServer(addr, psk string, ports, udpPorts []int) {
	p := &pool{}
	for _, port := range ports {
		go serveExposed(port, p)
	}
	for _, port := range udpPorts {
		go serveUDP(port, p)
	}
	l, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("waiting for tunnel on %s", addr)
	for {
		c, err := l.Accept()
		if err != nil {
			continue
		}
		go handleTunnel(c, psk, p)
	}
}

// ---------- client (kharej) ----------

func handleUDPStream(st net.Conn, port int) {
	defer st.Close()
	uc, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return
	}
	defer uc.Close()
	go func() { // local service -> tunnel
		b := make([]byte, 65535)
		for {
			uc.SetReadDeadline(time.Now().Add(udpIdle))
			n, err := uc.Read(b)
			if err != nil {
				st.Close()
				return
			}
			if writeDgram(st, b[:n]) != nil {
				return
			}
		}
	}()
	b := make([]byte, 65535)
	for { // tunnel -> local service
		n, err := readDgram(st, b)
		if err != nil {
			return
		}
		uc.Write(b[:n])
	}
}

func clientOnce(addr, psk string, allowed, allowedUDP map[int]bool) error {
	c, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return err
	}
	tune(c)
	sc, err := handshake(c, psk, true)
	if err != nil {
		c.Close()
		return err
	}
	sess, err := yamux.Client(sc, yamuxCfg())
	if err != nil {
		c.Close()
		return err
	}
	hs, err := sess.Open()
	if err != nil {
		return err
	}
	if err := writeHello(hs, allowed, allowedUDP); err != nil {
		return err
	}
	hs.Close()
	log.Printf("connected to %s", addr)
	for {
		st, err := sess.Accept()
		if err != nil {
			return err
		}
		go func() {
			var hdr [3]byte
			if _, err := io.ReadFull(st, hdr[:]); err != nil {
				st.Close()
				return
			}
			port := int(binary.BigEndian.Uint16(hdr[1:]))
			if hdr[0] == protoUDP {
				if !allowedUDP[port] {
					st.Close()
					return
				}
				handleUDPStream(st, port)
				return
			}
			if hdr[0] != protoTCP || !allowed[port] {
				st.Close()
				return
			}
			t, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 10*time.Second)
			if err != nil {
				st.Close()
				return
			}
			tune(t)
			pipe(st, t)
		}()
	}
}

func runClient(addr, psk string, ports, udpPorts []int, conns int) {
	allowed := map[int]bool{}
	for _, p := range ports {
		allowed[p] = true
	}
	allowedUDP := map[int]bool{}
	for _, p := range udpPorts {
		allowedUDP[p] = true
	}
	// addr may be a comma separated list: one kharej -> several Iran servers
	for _, target := range strings.Split(addr, ",") {
		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}
		for i := 0; i < conns; i++ {
			go func(target string, i int) {
				time.Sleep(time.Duration(i) * 300 * time.Millisecond)
				backoff := time.Second
				for {
					start := time.Now()
					err := clientOnce(target, psk, allowed, allowedUDP)
					log.Printf("[%s #%d] disconnected: %v", target, i, err)
					if time.Since(start) > time.Minute {
						backoff = time.Second
					}
					time.Sleep(backoff)
					if backoff < 30*time.Second {
						backoff *= 2
					}
				}
			}(target, i)
		}
	}
	select {}
}

func main() {
	mode := flag.String("mode", "", "server (Iran) or client (kharej)")
	key := flag.String("key", "", "pre-shared key (same on both sides)")
	tun := flag.String("tunnel", "", "server: listen addr (:4000); client: IRAN_IP:4000")
	ports := flag.String("ports", "", "comma separated TCP ports to forward, e.g. 443,8443")
	udp := flag.String("udp", "", "comma separated UDP ports to forward, e.g. 51820")
	bind := flag.String("bind", "", "server: IP that user-facing ports listen on (default: all)")
	pad := flag.Int("pad", 128, "max random padding bytes per frame (0 = off, max 4096)")
	conns := flag.Int("conns", 4, "client: number of parallel tunnel connections")
	flag.Parse()
	if *key == "" || *tun == "" || (*ports == "" && *udp == "") {
		flag.Usage()
		return
	}
	if *pad < 0 || *pad > 4096 {
		log.Fatal("-pad must be 0..4096")
	}
	padMax = *pad
	bindAddr = *bind
	switch *mode {
	case "server":
		runServer(*tun, *key, parsePorts(*ports), parsePorts(*udp))
	case "client":
		runClient(*tun, *key, parsePorts(*ports), parsePorts(*udp), *conns)
	default:
		flag.Usage()
	}
}
