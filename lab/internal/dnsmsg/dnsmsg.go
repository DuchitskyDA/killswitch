// Package dnsmsg — минимальные DNS-сообщения для проб: один вопрос, один ответ A или AAAA.
package dnsmsg

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"strings"
)

const (
	TypeA    = 1
	TypeAAAA = 28
	ClassIN  = 1
)

var ErrMalformed = errors.New("dnsmsg: неверное сообщение")

func encodeName(name string) ([]byte, error) {
	var b []byte
	for _, l := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		if len(l) == 0 || len(l) > 63 {
			return nil, ErrMalformed
		}
		b = append(b, byte(len(l)))
		b = append(b, l...)
	}
	return append(b, 0), nil
}

// Query — запрос с RD на имя name типа qtype.
func Query(id uint16, name string, qtype uint16) ([]byte, error) {
	n, err := encodeName(name)
	if err != nil {
		return nil, err
	}
	b := make([]byte, 12, 12+len(n)+4)
	binary.BigEndian.PutUint16(b[0:], id)
	binary.BigEndian.PutUint16(b[2:], 0x0100)
	binary.BigEndian.PutUint16(b[4:], 1)
	b = append(b, n...)
	return binary.BigEndian.AppendUint16(binary.BigEndian.AppendUint16(b, qtype), ClassIN), nil
}

// skipName возвращает смещение после имени (с учётом сжатия).
func skipName(m []byte, off int) (int, error) {
	for {
		if off >= len(m) {
			return 0, ErrMalformed
		}
		l := int(m[off])
		switch {
		case l == 0:
			return off + 1, nil
		case l&0xc0 == 0xc0:
			if off+2 > len(m) {
				return 0, ErrMalformed
			}
			return off + 2, nil
		case l > 63:
			return 0, ErrMalformed
		}
		off += 1 + l
	}
}

// Answer отвечает на запрос: A → a, AAAA → aaaa, остальное — пустой ответ.
func Answer(q []byte, a, aaaa netip.Addr) ([]byte, error) {
	if len(q) < 12 || binary.BigEndian.Uint16(q[4:]) != 1 || q[2]&0x80 != 0 {
		return nil, ErrMalformed
	}
	end, err := skipName(q, 12)
	if err != nil || end+4 > len(q) {
		return nil, ErrMalformed
	}
	qtype := binary.BigEndian.Uint16(q[end:])
	end += 4
	var rdata []byte
	switch qtype {
	case TypeA:
		v := a.As4()
		rdata = v[:]
	case TypeAAAA:
		v := aaaa.As16()
		rdata = v[:]
	}
	r := make([]byte, 0, end+16+len(rdata))
	r = binary.BigEndian.AppendUint16(r, binary.BigEndian.Uint16(q[0:]))
	r = binary.BigEndian.AppendUint16(r, 0x8180)
	r = binary.BigEndian.AppendUint16(r, 1)
	an := uint16(0)
	if rdata != nil {
		an = 1
	}
	r = binary.BigEndian.AppendUint16(r, an)
	r = append(r, 0, 0, 0, 0)
	r = append(r, q[12:end]...)
	if rdata != nil {
		r = append(r, 0xc0, 0x0c)
		r = binary.BigEndian.AppendUint16(r, qtype)
		r = binary.BigEndian.AppendUint16(r, ClassIN)
		r = binary.BigEndian.AppendUint32(r, 60)
		r = binary.BigEndian.AppendUint16(r, uint16(len(rdata)))
		r = append(r, rdata...)
	}
	return r, nil
}

// Addrs достаёт адреса A/AAAA из ответа на запрос id.
func Addrs(r []byte, id uint16) ([]netip.Addr, error) {
	if len(r) < 12 || binary.BigEndian.Uint16(r[0:]) != id || r[2]&0x80 == 0 {
		return nil, ErrMalformed
	}
	qd, an := int(binary.BigEndian.Uint16(r[4:])), int(binary.BigEndian.Uint16(r[6:]))
	off := 12
	for i := 0; i < qd; i++ {
		e, err := skipName(r, off)
		if err != nil {
			return nil, err
		}
		off = e + 4
	}
	var out []netip.Addr
	for i := 0; i < an; i++ {
		e, err := skipName(r, off)
		if err != nil || e+10 > len(r) {
			return nil, ErrMalformed
		}
		typ := binary.BigEndian.Uint16(r[e:])
		rdl := int(binary.BigEndian.Uint16(r[e+8:]))
		data := e + 10
		if data+rdl > len(r) {
			return nil, ErrMalformed
		}
		switch {
		case typ == TypeA && rdl == 4:
			out = append(out, netip.AddrFrom4([4]byte(r[data:data+4])))
		case typ == TypeAAAA && rdl == 16:
			out = append(out, netip.AddrFrom16([16]byte(r[data:data+16])))
		}
		off = data + rdl
	}
	return out, nil
}
