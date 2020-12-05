package group

// Element interface abstracts common operations on elements in a Group.
type Element interface {
	// Add returns the sum of the Elements, and does not change the receiver.
	Add(Element) Element

	// Sub returns the difference between the scalars, and does not change the receiver.
	Sub(Element) Element

	// Mult returns the scalar multiplication of the receiver element with the given scalar.
	Mult(Scalar) Element

	// InvertMult returns the scalar multiplication of the receiver element with the inverse of the given scalar.
	InvertMult(Scalar) Element

	// IsIdentity returns whether the element is the Group's identity element.
	IsIdentity() bool

	// Copy returns a copy of the element.
	Copy() Element

	// Decode decodes the input an sets the current element to its value, and returns it.
	Decode(in []byte) (Element, error)

	// Bytes returns the compressed byte encoding of the element.
	Bytes() []byte
}
