package internal

import "math/big"

type Field interface {
	New() FieldElement
	MinusOne() FieldElement
	Zero() FieldElement
	One() FieldElement
	Two() FieldElement

	Random() FieldElement

	Order() FieldElement
	Ext() FieldElement
	BitLen() FieldElement
}

type FieldElement interface {
	// One sets e = 1, and returns e.
	One() FieldElement

	// IsEqual returns true if e == t, and false otherwise.
	IsEqual(t FieldElement) bool

	// IsZero returns 1 if e == 0, and zero otherwise.
	IsZero() int

	// Set sets e = t, and returns e.
	Set(t FieldElement) FieldElement

	// Bytes returns the 66-byte big-endian encoding of e.
	Bytes() []byte

	SetInt(v *big.Int) (FieldElement, error)

	// SetBytes sets e = v, where v is a big-endian 66-byte encoding, and returns e.
	// If v is not 66 bytes or it encodes a value higher than the order,
	// SetBytes returns nil and an error, and e is unchanged.
	SetBytes(v []byte) (FieldElement, error)

	// Add sets e = t1 + t2, and returns e.
	Add(t1, t2 FieldElement) FieldElement

	// Sub sets e = t1 - t2, and returns e.
	Subtract(t1, t2 FieldElement) FieldElement

	// Multiply sets e = t1 * t2, and returns e.
	Multiply(t1, t2 FieldElement) FieldElement

	// Square sets e = t * t, and returns e.
	Square(t FieldElement) FieldElement

	// Select sets v to a if cond == 1, and to b if cond == 0.
	Select(t1, t2 FieldElement, cond int) FieldElement

	Swap(t FieldElement, condition bool)

	// IsSquare returns whether the element is a quadratic square.
	IsSquare() bool

	//
	Negate(t FieldElement) FieldElement

	Invert(t FieldElement) FieldElement

	// = t1^t2
	Exp(t1, t2 FieldElement) FieldElement

	SqrtRatio(t1, t2 FieldElement) (FieldElement, int)
}

type Curve interface {
	SqrtRatio(e, v FieldElement)
	Map(e FieldElement) CurvePoint
}

type CurvePoint interface {
	Identity() CurvePoint
	Neg() CurvePoint

	Bytes() CurvePoint
	Copy() CurvePoint
	Decode(input []byte) (CurvePoint, error)

	IsIdentity() bool
	IsEqual(q CurvePoint) bool
	IsTwoTorsion() bool

	Add(q, r CurvePoint) CurvePoint
	Double(q CurvePoint) CurvePoint
	ScalarMult(q CurvePoint, e FieldElement) CurvePoint
}
