package encoding

import (
	"encoding/binary"
	"errors"
)

const (
	i2ospMaxInt8  = (1 << 8) - 1  // 255 - FF
	i2ospMaxInt16 = (1 << 16) - 1 // 65535 - FFFF
	i2ospMaxInt24 = (1 << 24) - 1 // FFFF FFFF
	i2ospMaxInt32 = (1 << 32) - 1 // FFFF FFFF
	// i2ospMaxInt64 = (1 << 64) - 1
)

var (
	errI2OSPNegative = errors.New("forbidden negative value")
	errI2OSPLarge    = errors.New("integer too large : > 2^32")
)

// I2OSP1 Integer to Octet Stream Primitive on 1 byte.
func I2OSP1(in uint) []byte {
	if in > i2ospMaxInt8 {
		panic("input is to big")
	}

	out := make([]byte, 2)

	binary.BigEndian.PutUint16(out, uint16(in))

	return out[1:]
}

// I2OSP2 Integer to Octet Stream Primitive on 2 bytes.
func I2OSP2(in uint) []byte {
	if in > i2ospMaxInt16 {
		panic("input is to big")
	}

	out := make([]byte, 2)

	binary.BigEndian.PutUint16(out, uint16(in))

	return out
}

// I2OSP Integer to Octet Stream Primitive on maximum 4 bytes.
func I2OSP(in int) []byte {
	if in < 0 {
		panic(errI2OSPNegative)
	}

	max := 4
	out := make([]byte, max)

	switch ll := in; {
	case ll <= i2ospMaxInt8:
		binary.BigEndian.PutUint16(out, uint16(in))

		return out[1:2]
	case ll <= i2ospMaxInt16:
		binary.BigEndian.PutUint16(out, uint16(in))

		return out[:2]
	case ll <= i2ospMaxInt24:
		binary.BigEndian.PutUint16(out, uint16(in))

		return out[:3]
	case ll <= i2ospMaxInt32:
		binary.BigEndian.PutUint32(out, uint32(in))

		return out
	// case ll <= i2ospMaxInt64:
	// 	binary.BigEndian.PutUint64(out, uint64(in))
	// 	size := (int)(math.Log2(float64(in)/(float64(max))))
	// 	return out[max-size:]
	default:
		panic(errI2OSPLarge)
	}
}
