package kdb

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"reflect"
	"time"
	"unsafe"

	"github.com/nu7hatch/gouuid"
)

var typeSize = map[int8]int{
	1: 1, 4: 1, 10: 1,
	2: 16,
	5: 2,
	6: 4, 8: 4, 13: 4, 14: 4, 17: 4, 18: 4, 19: 4,
	7: 8, 9: 8, 12: 8, 15: 8, 16: 8}

var typeReflect = map[int8]reflect.Type{
	1:  reflect.TypeOf([]bool{}),
	2:  reflect.TypeOf([]uuid.UUID{}),
	4:  reflect.TypeOf([]byte{}),
	5:  reflect.TypeOf([]int16{}),
	6:  reflect.TypeOf([]int32{}),
	7:  reflect.TypeOf([]int64{}),
	8:  reflect.TypeOf([]float32{}),
	9:  reflect.TypeOf([]float64{}),
	10: reflect.TypeOf([]byte{}),
	12: reflect.TypeOf([]int64{}),
	13: reflect.TypeOf([]Month{}),
	14: reflect.TypeOf([]int32{}),
	15: reflect.TypeOf([]float64{}),
	16: reflect.TypeOf([]time.Duration{}),
	17: reflect.TypeOf([]int32{}),
	18: reflect.TypeOf([]int32{}),
	19: reflect.TypeOf([]int32{})}

func makeArray(vectype int8, veclen int) interface{} {
	switch vectype {
	case 1:
		return make([]bool, veclen)
	case 4, 10:
		return make([]byte, veclen)
	case 2:
		return make([]uuid.UUID, veclen)
	case 5:
		return make([]int16, veclen)
	case 6, 14, 17, 18, 19:
		return make([]int32, veclen)
	case 13:
		return make([]Month, veclen)
	case 16:
		return make([]time.Duration, veclen)
	case 7, 12:
		return make([]int64, veclen)
	case 8:
		return make([]float32, veclen)
	case 9, 15:
		return make([]float64, veclen)
	case 11:
		return make([]string, veclen)
	}

	return nil
}

func (h *ipcHeader) getByteOrder() binary.ByteOrder {
	var order binary.ByteOrder
	order = binary.LittleEndian
	if h.ByteOrder == 0x00 {
		order = binary.BigEndian
	}
	return order
}

func (h *ipcHeader) ok() bool {
	return h.ByteOrder == 0x01 && h.RequestType < 3 && h.Compressed < 0x02 && h.MsgSize > 9
}

// Ucompress byte array compressed with Q IPC compression
func Uncompress(b []byte) (dst []byte) {
	if len(b) < 4+1 {
		return b
	}
	n, r, f, s := int32(0), int32(0), int32(0), int32(8)
	p := int32(s)
	i := int16(0)
	var usize int32
	binary.Read(bytes.NewReader(b[0:4]), binary.LittleEndian, &usize)
	dst = make([]byte, usize)
	d := int32(4)
	aa := make([]int32, 256)
	for int(s) < len(dst) {
		if i == 0 {
			f = 0xff & int32(b[d])
			d++
			i = 1
		}
		if (f & int32(i)) != 0 {
			r = aa[0xff&int32(b[d])]
			d++
			dst[s] = dst[r]
			s++
			r++
			dst[s] = dst[r]
			s++
			r++
			n = 0xff & int32(b[d])
			d++
			for m := int32(0); m < n; m++ {
				dst[s+m] = dst[r+m]
			}
		} else {
			dst[s] = b[d]
			s++
			d++
		}
		for p < s-1 {
			aa[(0xff&int32(dst[p]))^(0xff&int32(dst[p+1]))] = p
			p++
		}
		if (f & int32(i)) != 0 {
			s += n
			p = s
		}
		i *= 2
		if i == 256 {
			i = 0
		}
	}
	return dst
}

// Decodes data from src in q ipc format.
func Decode(src *bufio.Reader) (*K, int, error) {
	var header ipcHeader
	err := binary.Read(src, binary.LittleEndian, &header)
	if err != nil {
		return nil, -1, errors.New("Failed to read message header:" + err.Error())
	}
	if !header.ok() {
		return nil, -1, errors.New("header is invalid")
	}
	// try to buffer entire message in one go
	src.Peek(int(header.MsgSize - 8))

	var order = header.getByteOrder()
	if header.Compressed == 0x01 {
		compressed := make([]byte, header.MsgSize-8)
		_, err = io.ReadFull(src, compressed)
		if err != nil {
			return nil, int(header.RequestType), errors.New("Decode:readcompressed error - " + err.Error())
		}
		var uncompressed = Uncompress(compressed)
		var buf = bufio.NewReader(bytes.NewReader(uncompressed[8:]))
		data, err := readData(buf, order)
		return data, int(header.RequestType), err
	}
	data, err := readData(src, order)
	return data, int(header.RequestType), err
}

func readData(r *bufio.Reader, order binary.ByteOrder) (*K, error) {
	var msgtype int8
	if err := binary.Read(r, order, &msgtype); err != nil {
		return nil, err
	}

	switch msgtype {
	case -KB:
		var b byte
		binary.Read(r, order, &b)
		return &K{msgtype, NONE, b != 0x0}, nil
	case -UU:
		var u uuid.UUID
		binary.Read(r, order, &u)
		return &K{msgtype, NONE, u}, nil
	case -KG:
		var b byte
		binary.Read(r, order, &b)
		return &K{msgtype, NONE, b}, nil
	case -KH:
		var sh int16
		binary.Read(r, order, &sh)
		return &K{msgtype, NONE, sh}, nil
	case -KI, -KU, -KV:
		var i int32
		binary.Read(r, order, &i)
		return &K{msgtype, NONE, i}, nil
	case -KJ:
		var j int64
		binary.Read(r, order, &j)
		return &K{msgtype, NONE, j}, nil
	case -KE:
		var e float32
		binary.Read(r, order, &e)
		return &K{msgtype, NONE, e}, nil
	case -KF, -KZ:
		var f float64
		binary.Read(r, order, &f)
		return &K{msgtype, NONE, f}, nil
	case -KC:
		var c byte
		binary.Read(r, order, &c)
		return &K{msgtype, NONE, c}, nil // should be rune?
	case -KS:
		line, err := r.ReadBytes(0)
		if err != nil {
			return nil, err
		}
		str := string(line[:len(line)-1])
		return &K{msgtype, NONE, str}, nil
	case -KP:
		var nanos int64
		binary.Read(r, order, &nanos)
		return Timestamp(qEpoch.Add(time.Duration(nanos))), nil
	case -KM:
		var m Month
		binary.Read(r, order, &m)
		return &K{msgtype, NONE, m}, nil
	case -KD:
		var days int32
		binary.Read(r, order, &days)
		return Date(time.Unix((int64(days)*86400)+qEpoch.Unix(), 0)), nil
	case -KN:
		var span time.Duration
		binary.Read(r, order, &span)
		return &K{msgtype, NONE, span}, nil
	case -KT:
		var millis int32
		binary.Read(r, order, &millis)
		return Time(time.Unix(0, int64(millis)*int64(time.Millisecond))), nil
	case KB, UU, KG, KH, KI, KJ, KE, KF, KC, KP, KM, KD, KN, KU, KV, KT, KZ:
		var vecattr Attr
		if err := binary.Read(r, order, &vecattr); err != nil {
			return nil, errors.New("failed to read vector attr: " + err.Error())
		}

		var veclen uint32
		if err := binary.Read(r, order, &veclen); err != nil {
			return nil, errors.New("failed to read vector length: " + err.Error())
		}

		var arr interface{}
		if msgtype >= KB && msgtype <= KT {
			bytedata := make([]byte, int(veclen)*typeSize[msgtype])
			if _, err := io.ReadFull(r, bytedata); err != nil {
				return nil, errors.New("failed to read. not enough data: " + err.Error())
			}
			head := (*reflect.SliceHeader)(unsafe.Pointer(&bytedata))
			head.Len = int(veclen)
			head.Cap = int(veclen)
			arr = reflect.Indirect(reflect.NewAt(typeReflect[msgtype], unsafe.Pointer(&bytedata))).Interface()
		} else {
			arr = makeArray(msgtype, int(veclen))
			if err := binary.Read(r, order, arr); err != nil {
				return nil, errors.New("error during conversion: " + err.Error())
			}
		}

		switch msgtype {
		case KC:
			return String(string(arr.([]byte))), nil
		case KP:
			var vec = make([]time.Time, veclen)
			for i, nanos := range arr.([]int64) {
				vec[i] = qEpoch.Add(time.Duration(nanos))
			}
			return TimestampV(vec), nil
		case KD:
			var vec = make([]time.Time, veclen)
			for i, days := range arr.([]int32) {
				vec[i] = time.Unix((int64(days)*86400)+qEpoch.Unix(), 0)
			}
			return DateV(vec), nil
		case KZ:
			arr := arr.([]float64)
			var timearr = make([]time.Time, veclen)
			for i := 0; i < int(veclen); i++ {
				d := time.Duration(86400000*arr[i]) * time.Millisecond
				timearr[i] = qEpoch.Add(d)
			}
			return &K{msgtype, vecattr, timearr}, nil
		case KU:
			arr := arr.([]int32)
			var timearr = make([]Minute, veclen)
			for i := 0; i < int(veclen); i++ {
				d := time.Duration(arr[i]) * time.Minute
				timearr[i] = Minute(time.Time{}.Add(d))
			}
			return &K{msgtype, vecattr, timearr}, nil
		case KV:
			arr := arr.([]int32)
			var timearr = make([]Second, veclen)
			for i := 0; i < int(veclen); i++ {
				d := time.Duration(arr[i]) * time.Second
				timearr[i] = Second(time.Time{}.Add(d))
			}
			return &K{msgtype, vecattr, timearr}, nil
		}
		if msgtype == KT {
			var vec = make([]time.Time, veclen)
			for i, millis := range arr.([]int32) {
				vec[i] = time.Unix(0, int64(millis)*int64(time.Millisecond))
			}
			return TimeV(vec), nil
		}
		return &K{msgtype, vecattr, arr}, nil
	case K0:
		var vecattr Attr
		if err := binary.Read(r, order, &vecattr); err != nil {
			return nil, errors.New("failed to read vector attr: " + err.Error())
		}
		var veclen uint32
		if err := binary.Read(r, order, &veclen); err != nil {
			return nil, errors.New("failed to read vector length: " + err.Error())
		}
		var arr = make([]*K, veclen)
		for i := 0; i < int(veclen); i++ {
			v, err := readData(r, order)
			if err != nil {
				return nil, err
			}
			arr[i] = v
		}
		return &K{msgtype, vecattr, arr}, nil
	case KS:
		var vecattr Attr
		if err := binary.Read(r, order, &vecattr); err != nil {
			return nil, errors.New("failed to read vector attr: " + err.Error())
		}
		var veclen uint32
		if err := binary.Read(r, order, &veclen); err != nil {
			return nil, errors.New("failed to read vector length: " + err.Error())
		}
		var arr = makeArray(msgtype, int(veclen)).([]string)
		for i := 0; i < int(veclen); i++ {
			line, err := r.ReadSlice(0)
			if err != nil {
				return nil, err
			}
			arr[i] = string(line[:len(line)-1])
		}
		return &K{msgtype, vecattr, arr}, nil
	case XD, SD:
		dk, err := readData(r, order)
		if err != nil {
			return nil, err
		}
		dv, err := readData(r, order)
		if err != nil {
			return nil, err
		}
		return NewDict(dk, dv), nil
	case XT:
		var vecattr Attr
		if err := binary.Read(r, order, &vecattr); err != nil {
			return nil, errors.New("failed to read vector attr: " + err.Error())
		}
		d, err := readData(r, order)
		if err != nil {
			return nil, err
		}
		if d.Type != XD {
			return nil, errors.New("expected dict")
		}
		dict := d.Data.(Dict)
		colNames := dict.Key.Data.([]string)
		colValues := dict.Value.Data.([]*K)
		return &K{msgtype, vecattr, Table{colNames, colValues}}, nil

	case KFUNC:
		var f Function
		line, err := r.ReadSlice(0)
		if err != nil {
			return nil, err
		}
		f.Namespace = string(line[:len(line)-1])
		b, err := readData(r, order)
		if err != nil {
			return nil, err
		}
		if b.Type != KC {
			return nil, errors.New("expected string")
		}
		f.Body = b.Data.(string)
		return &K{msgtype, NONE, f}, nil
	case KFUNCUP, KFUNCBP, KFUNCTR:
		var primitiveidx byte
		if err := binary.Read(r, order, &primitiveidx); err != nil {
			return nil, err
		}
		return &K{msgtype, NONE, primitiveidx}, nil
	case KPROJ, KCOMP:
		var n uint32
		if err := binary.Read(r, order, &n); err != nil {
			return nil, err
		}
		var res = make([]interface{}, n)
		for i := 0; i < int(n); i++ {
			var err error
			if res[i], err = readData(r, order); err != nil {
				return nil, err
			}
		}
		return &K{msgtype, NONE, res}, nil
	case KEACH, KOVER, KSCAN, KPRIOR, KEACHRIGHT, KEACHLEFT:
		return readData(r, order)
	case KDYNLOAD:
		// 112 - dynamic load
		return nil, errors.New("type is unsupported")
	case KERR:
		line, err := r.ReadSlice(0)
		if err != nil {
			return nil, err
		}
		errmsg := string(line[:len(line)-1])
		return nil, errors.New(errmsg)
	}
	return nil, ErrBadMsg
}
