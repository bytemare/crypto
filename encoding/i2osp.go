package encoding

import (
	"encoding/binary"
	"errors"
)

const (
	i2ospMaxInt8  = (1 << 8) - 1  // FF = 255
	i2ospMaxInt16 = (1 << 16) - 1 // FFFF = 65535
	i2ospMaxInt24 = (1 << 24) - 1 // FF FFFF = 16777215
	i2ospMaxInt32 = (1 << 32) - 1 // FFFF FFFF = 4294967295
)

var (
	errInputNegative  = errors.New("negative input")
	errInputLarge32   = errors.New("integer too large : > 2^32")
	errInputLarge     = errors.New("input is too high for length")
	errLengthNegative = errors.New("length is negative or 0")
	errLengthTooBig   = errors.New("requested length is > 4")

	errInputEmpty    = errors.New("nil or empty input")
	errInputTooLarge = errors.New("input too large for integer")
)

func i2osp2(in, size, max uint) []byte {
	if in > max {
		panic(errInputLarge)
	}

	out := make([]byte, 2)

	binary.BigEndian.PutUint16(out, uint16(in))

	return out[2-size:]
}

// I2OSP1 Integer to Octet Stream Primitive on 1 byte.
func I2OSP1(in uint) []byte {
	return i2osp2(in, 1, i2ospMaxInt8)
}

// I2OSP2 Integer to Octet Stream Primitive on 2 bytes.
func I2OSP2(in uint) []byte {
	return i2osp2(in, 2, i2ospMaxInt16)
}

// I2OSP 32 bit Integer to Octet Stream Primitive on maximum 4 bytes.
func I2OSP(input, length int) []byte {
	if length <= 0 {
		panic(errLengthNegative)
	}

	if length > 4 {
		panic(errLengthTooBig)
	}

	out := make([]byte, 4)

	switch in := input; {
	case in < 0:
		panic(errInputNegative)

	case in >= 1<<(8*length):
		panic(errInputLarge)

	case in <= i2ospMaxInt8:
		binary.BigEndian.PutUint16(out, uint16(in))

		return out[1:2]
	case in <= i2ospMaxInt16:
		binary.BigEndian.PutUint16(out, uint16(in))

		return out[:2]
	case in <= i2ospMaxInt24:
		binary.BigEndian.PutUint32(out, uint32(in))

		return out[:3]
	case in <= i2ospMaxInt32:
		binary.BigEndian.PutUint32(out, uint32(in))

		return out
	default:
		panic(errInputLarge32)
	}
}

// I2OSP Octet Stream to Integer Primitive on maximum 4 bytes / 32 bits.
func OS2IP(input []byte) int {
	switch length := len(input); {
	case length == 0:
		panic(errInputEmpty)
	case length == 1:
		b := []byte{0, input[0]}
		return int(binary.BigEndian.Uint16(b))
	case length == 2:
		return int(binary.BigEndian.Uint16(input))
	case length == 3:
		b := append([]byte{0}, input...)
		return int(binary.BigEndian.Uint16(b))
	case length == 4:
		return int(binary.BigEndian.Uint32(input))
	default:
		panic(errInputTooLarge)
	}
}
