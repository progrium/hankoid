package gateway

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
)

// 9P framing and the few messages the gateway reads: size[4] type[1] tag[2] body.

const (
	tRlerror  = 7
	tTversion = 100
	tRversion = 101
	tTauth    = 102
	tTattach  = 104
	tRerror   = 107
	tTrebind  = 250 // 9P2000.L.Z

	noFid    = ^uint32(0)
	noUname  = ^uint32(0)
	noTag    = ^uint16(0)
	headerSz = 7

	// Before a version is negotiated, a message may be at most this big.
	preVersionMax = 8192
)

// Dialects the gateway understands. They share framing; Tattach and errors differ.
const (
	V9P2000   = "9P2000"
	V9P2000u  = "9P2000.u"
	V9P2000L  = "9P2000.L"
	V9P2000LZ = "9P2000.L.Z"
)

var knownVersions = []string{V9P2000LZ, V9P2000L, V9P2000u, V9P2000}

// hasNUname reports whether the dialect's Tattach (and Tauth) carry n_uname[4].
func hasNUname(v string) bool { return v != V9P2000 }

// isDotL reports whether the dialect answers errors with Rlerror.
func isDotL(v string) bool { return v == V9P2000L || v == V9P2000LZ }

var errTooBig = errors.New("9p message exceeds msize")

// readMsg reads one whole 9P message, at most max bytes.
func readMsg(r *bufio.Reader, max uint32) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.LittleEndian.Uint32(hdr[:])
	if n < headerSz {
		return nil, fmt.Errorf("9p message too short (%d bytes)", n)
	}
	if n > max {
		return nil, errTooBig
	}
	m := make([]byte, n)
	copy(m, hdr[:])
	if _, err := io.ReadFull(r, m[4:]); err != nil {
		return nil, err
	}
	return m, nil
}

func msgType(m []byte) byte  { return m[4] }
func msgTag(m []byte) uint16 { return binary.LittleEndian.Uint16(m[5:]) }

// decoder reads fields from a message body.
type decoder struct {
	b   []byte
	err error
}

func (d *decoder) u32() uint32 {
	if d.err != nil || len(d.b) < 4 {
		d.err = errors.New("9p message truncated")
		return 0
	}
	v := binary.LittleEndian.Uint32(d.b)
	d.b = d.b[4:]
	return v
}

func (d *decoder) str() string {
	if d.err != nil || len(d.b) < 2 {
		d.err = errors.New("9p message truncated")
		return ""
	}
	n := int(binary.LittleEndian.Uint16(d.b))
	if len(d.b) < 2+n {
		d.err = errors.New("9p message truncated")
		return ""
	}
	s := string(d.b[2 : 2+n])
	d.b = d.b[2+n:]
	return s
}

// encoder builds a message; finish fills in the size.
type encoder struct{ b []byte }

func newMsg(typ byte, tag uint16) *encoder {
	e := &encoder{b: make([]byte, headerSz, 64)}
	e.b[4] = typ
	binary.LittleEndian.PutUint16(e.b[5:], tag)
	return e
}

func (e *encoder) u32(v uint32) *encoder { e.b = binary.LittleEndian.AppendUint32(e.b, v); return e }
func (e *encoder) str(s string) *encoder {
	if len(s) > 0xffff {
		s = s[:0xffff]
	}
	e.b = binary.LittleEndian.AppendUint16(e.b, uint16(len(s)))
	e.b = append(e.b, s...)
	return e
}
func (e *encoder) finish() []byte {
	binary.LittleEndian.PutUint32(e.b, uint32(len(e.b)))
	return e.b
}

type version struct {
	msize   uint32
	version string
}

func parseVersion(m []byte) (version, error) {
	d := &decoder{b: m[headerSz:]}
	v := version{msize: d.u32(), version: d.str()}
	return v, d.err
}

func versionMsg(typ byte, tag uint16, v version) []byte {
	return newMsg(typ, tag).u32(v.msize).str(v.version).finish()
}

type attach struct {
	fid, afid    uint32
	uname, aname string
	nUname       uint32
}

func parseAttach(m []byte, dialect string) (attach, error) {
	d := &decoder{b: m[headerSz:]}
	a := attach{fid: d.u32(), afid: d.u32(), uname: d.str(), aname: d.str(), nUname: noUname}
	if hasNUname(dialect) {
		a.nUname = d.u32()
	}
	return a, d.err
}

func attachMsg(tag uint16, a attach, dialect string) []byte {
	e := newMsg(tTattach, tag).u32(a.fid).u32(a.afid).str(a.uname).str(a.aname)
	if hasNUname(dialect) {
		e.u32(a.nUname)
	}
	return e.finish()
}

// errorMsg is the dialect's error reply: Rlerror with an errno for .L, otherwise Rerror with a
// string (and an errno for .u).
func errorMsg(tag uint16, dialect, text string, errno uint32) []byte {
	if isDotL(dialect) {
		return newMsg(tRlerror, tag).u32(errno).finish()
	}
	e := newMsg(tRerror, tag).str(text)
	if dialect == V9P2000u {
		e.u32(errno)
	}
	return e.finish()
}

const (
	errnoEPERM      = 1
	errnoEOPNOTSUPP = 95
)

// pickVersion chooses what to offer the backend for a client's version string: the client's
// own if the route allows it, or else the most specific allowed dialect the client's extends
// (a 9P2000.L.Z client may be offered 9P2000.L), as version(5) lets a server answer lower.
func pickVersion(client string, allowed []string) string {
	best := ""
	for _, v := range allowed {
		if (client == v || strings.HasPrefix(client, v+".")) && len(v) > len(best) {
			best = v
		}
	}
	return best
}
