package group

// Element interface abstracts common operations on elements in a Group.
type Element interface {
	// Add adds the argument to the receiver, sets the receiver to the result and returns it.
	Add(Element) Element

	// Sub subtracts the argument from the receiver, sets the receiver to the result and returns it.
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

	// Bytes returns the byte encoding of the element.
	Bytes() []byte
}
