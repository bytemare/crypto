package internal

// GenericGroup abstracts operations in a prime-order group.
type GenericGroup[Scalar GenericScalar[Scalar], Element GenericElement[Scalar, Element]] interface {
	// NewScalar returns a new, empty, scalar.
	NewScalar() Scalar

	// NewElement returns the identity point (point at infinity).
	NewElement() Element

	// ElementLength returns the byte size of an encoded element.
	ElementLength() uint

	// HashToGroup allows arbitrary input to be safely mapped to the curve of the Group.
	HashToGroup(input, dst []byte) Element

	// EncodeToGroup allows arbitrary input to be mapped non-uniformly to points in the Group.
	EncodeToGroup(input, dst []byte) Element

	// HashToScalar allows arbitrary input to be safely mapped to the field.
	HashToScalar(input, dst []byte) Scalar

	// Base returns the group's base point a.k.a. canonical generator.
	Base() Element

	// MultBytes allows []byte encodings of a scalar and an element of the Group to be multiplied.
	MultBytes(scalar, element []byte) (Element, error)
}

// GenericElement interface abstracts common operations on an Element in a prime-order Group.
type GenericElement[Scalar GenericScalar[Scalar], Element any] interface {
	// Add returns the sum of the Elements, and does not change the receiver.
	Add(Element) Element

	// Sub returns the difference between the Elements, and does not change the receiver.
	Sub(Element) Element

	// Mult returns the scalar multiplication of the receiver with the given Scalar.
	Mult(Scalar) Element

	// InvertMult returns the scalar multiplication of the receiver with the inverse of s.
	InvertMult(s Scalar) Element

	// IsIdentity returns whether the Element is the point at infinity of the Group's underlying curve.
	IsIdentity() bool

	// Copy returns a copy of the Element.
	Copy() Element

	// Decode decodes the input a sets the receiver to its value, and returns it.
	Decode(in []byte) (Element, error)

	// Bytes returns the compressed byte encoding of the point.
	Bytes() []byte
}

// GenericScalar interface abstracts common operations on scalars in a prime-order Group.
type GenericScalar[Scalar any] interface {
	// Random sets the current scalar to a new random scalar and returns it.
	Random() Scalar

	// Add returns the sum of the scalars, and does not change the receiver.
	Add(scalar Scalar) Scalar

	// Sub returns the difference between the scalars, and does not change the receiver.
	Sub(scalar Scalar) Scalar

	// Mult returns the multiplication of the scalars, and does not change the receiver.
	Mult(scalar Scalar) Scalar

	// Invert returns the scalar's modular inverse ( 1 / scalar ), and does not change the receiver.
	Invert() Scalar

	// IsZero returns whether the scalar is 0.
	IsZero() bool

	// Copy returns a copy of the Scalar.
	Copy() Scalar

	// Decode decodes the input an sets the current scalar to its value, and returns it.
	Decode(in []byte) (Scalar, error)

	// Bytes returns the byte encoding of the element.
	Bytes() []byte
}
