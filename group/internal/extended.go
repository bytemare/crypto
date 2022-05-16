package internal

import "encoding"

type ECParams interface {
	FieldOrder() []byte
}

type ExtendedCurve interface {
	ECParams
}

type GroupElement interface {
	HashToPoint(input, dst []byte)
	EncodeToPoint(input, dst []byte)
	Order() []byte
	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler
}

type GroupScalar interface {
	HashToScalar(input, dst []byte)
	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler
}

type ECGroup interface {
	Group
	Order()
	ElementLength() uint
	ScalarLength() uint
	HashToPoint(input, dst []byte) GroupElement
	EncodeToPoint(input, dst []byte) GroupElement
	//HashToScalar(input, dst []byte) GroupScalar
}
