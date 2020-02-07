package kdb

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"reflect"
	"sync"
	"time"
)

// TODO: Handle all the errors returned by `Write` calls
// To read more about Qipc protocol, see https://code.kx.com/wiki/Reference/ipcprotocol
// Negative types are scalar and positive ones are vector. 0 is mixed list
func writeData(dbuf *bytes.Buffer, order binary.ByteOrder, data *K) error {
	binary.Write(dbuf, order, data.Type)

	// For all vector types, write the attribute (s,u,p,g OR none) & length of the vector
	if K0 <= data.Type && data.Type <= KT {
		binary.Write(dbuf, order, data.Attr)
		binary.Write(dbuf, order, int32(reflect.ValueOf(data.Data).Len()))
	} else if data.Type == XT { // For table only write the attribute
		binary.Write(dbuf, order, data.Attr)
	}

	switch data.Type {
	case K0: // Mixed List
		for _, k := range data.Data.([]*K) {
			if err := writeData(dbuf, order, k); err != nil {
				return err
			}
		}
	case -KB, -UU, -KG, -KH, -KI, -KJ, -KE, -KF, -KC, -KM, -KZ, -KN, -KU, -KV,
		KB, UU, KG, KH, KI, KJ, KE, KF, KM, KZ, KN, KU, KV: // Bool, Int, Float, and Byte
		// Note: UUID is backed by byte array of length 16
		binary.Write(dbuf, order, data.Data)
	case KC: // String
		dbuf.WriteString(data.Data.(string))
	case -KS: // Symbol
		dbuf.WriteString(data.Data.(string))
		binary.Write(dbuf, order, byte(0)) // Null terminator
	case KS: // Symbol
		for _, symbol := range data.Data.([]string) {
			dbuf.WriteString(symbol)
			binary.Write(dbuf, order, byte(0)) // Null terminator
		}
	case -KP: // Timestamp
		binary.Write(dbuf, order, data.Data.(time.Time).Sub(qEpoch))
	case KP: // Timestamp
		for _, ts := range data.Data.([]time.Time) {
			binary.Write(dbuf, order, ts.Sub(qEpoch))
		}
	case -KD: // Date
		date := data.Data.(time.Time)
		days := (date.Truncate(time.Hour * 24).Unix() - qEpoch.Unix()) / 86400
		binary.Write(dbuf, order, int32(days))
	case KD: // Date
		for _, date := range data.Data.([]time.Time) {
			days := (date.Truncate(time.Hour * 24).Unix() - qEpoch.Unix()) / 86400
			binary.Write(dbuf, order, int32(days))
		}
	case -KT: // Time
		t := data.Data.(time.Time)
		nanos := time.Duration(t.Hour())*time.Hour +
			time.Duration(t.Minute())*time.Minute +
			time.Duration(t.Second())*time.Second +
			time.Duration(t.Nanosecond())
		binary.Write(dbuf, order, int32(nanos/time.Millisecond))
	case KT: // Time
		for _, t := range data.Data.([]time.Time) {
			nanos := time.Duration(t.Hour())*time.Hour +
				time.Duration(t.Minute())*time.Minute +
				time.Duration(t.Second())*time.Second +
				time.Duration(t.Nanosecond())
			binary.Write(dbuf, order, int32(nanos/time.Millisecond))
		}
	case XD: // Dictionary
		dict := data.Data.(Dict)
		err := writeData(dbuf, order, dict.Key)
		if err != nil {
			return err
		}
		err = writeData(dbuf, order, dict.Value)
		if err != nil {
			return err
		}
	case XT: // Table
		table := data.Data.(Table)
		err := writeData(dbuf, order, NewDict(SymbolV(table.Columns), Enlist(table.Data...)))
		if err != nil {
			return err
		}
	case KERR:
		err := data.Data.(error)
		dbuf.WriteString(err.Error())
		binary.Write(dbuf, order, byte(0)) // Null terminator
	case KFUNC:
		fn := data.Data.(Function)
		dbuf.WriteString(fn.Namespace)
		binary.Write(dbuf, order, byte(0)) // Null terminator
		err := writeData(dbuf, order, String(fn.Body))
		if err != nil {
			return err
		}
	default:
		return NewUnsupportedTypeError(fmt.Sprintf("Unsupported Type: %d", data.Type))
	}
	return nil
}

func min32(a, b int32) int32 {
	if a > b {
		return b
	}
	return a
}

// Compress b using Q IPC compression
func Compress(b []byte) (dst []byte) {
	if len(b) <= 17 {
		return b
	}
	i := byte(0)
	//j := int32(len(b))
	f, h0, h := int32(0), int32(0), int32(0)
	g := false
	dst = make([]byte, len(b)/2)
	lenbuf := make([]byte, 4)
	c := 12
	d := c
	e := len(dst)
	p := 0
	q, r, s0 := int32(0), int32(0), int32(0)
	s := int32(8)
	t := int32(len(b))
	a := make([]int32, 256)
	copy(dst[:4], b[:4])
	dst[2] = 1
	binary.LittleEndian.PutUint32(lenbuf, uint32(len(b)))
	copy(dst[8:], lenbuf)
	for ; s < t; i *= 2 {
		if 0 == i {
			if d > e-17 {
				return b
			}
			i = 1
			dst[c] = byte(f)
			c = d
			d++
			f = 0
		}

		g = s > t-3
		if !g {
			h = int32(0xff & (b[s] ^ b[s+1]))
			p = int(a[h])
			g = (0 == p) || (0 != (b[s] ^ b[p]))
		}

		if 0 < s0 {
			a[h0] = s0
			s0 = 0
		}
		if g {
			h0 = h
			s0 = s
			dst[d] = b[s]
			d++
			s++
		} else {
			a[h] = s
			f |= int32(i)
			p += 2
			s += 2
			r = s
			q = min32(s+255, t)
			for ; b[p] == b[s] && s+1 < q; s++ {
				p++
			}
			dst[d] = byte(h)
			d++
			dst[d] = byte(s - r)
			d++
		}
	}
	dst[c] = byte(f)
	binary.LittleEndian.PutUint32(lenbuf, uint32(d))
	copy(dst[4:], lenbuf)
	return dst[:d:d]
}

// buffer pool to reduce GC
var buffers = sync.Pool{
	// New is called when a new instance is needed
	New: func() interface{} {
		return new(bytes.Buffer)
	},
}

// GetBuffer fetches a buffer from the pool
func GetBuffer() *bytes.Buffer {
	return buffers.Get().(*bytes.Buffer)
}

// PutBuffer returns a buffer to the pool
func PutBuffer(buf *bytes.Buffer) {
	buf.Reset()
	buffers.Put(buf)
}

// Encode data to ipc format as msgtype(sync/async/response) to specified writer
func Encode(w io.Writer, msgtype int, data *K) error {
	var order = binary.LittleEndian
	buf := GetBuffer()
	defer PutBuffer(buf)

	// As a place holder header, write 8 bytes to the buffer
	header := [8]byte{}
	if _, err := buf.Write(header[:]); err != nil {
		return err
	}

	// Then write the qipc encoded data
	if err := writeData(buf, order, data); err != nil {
		return err
	}

	// Now that we have the length of the buffer, create the correct header
	header[0] = 1 // byte order
	header[1] = byte(msgtype)
	header[2] = 0
	header[3] = 0
	order.PutUint32(header[4:], uint32(buf.Len()))

	// Write the correct header to the original buffer
	b := buf.Bytes()
	copy(b, header[:])

	_, err := w.Write(Compress(b))
	return err
}
