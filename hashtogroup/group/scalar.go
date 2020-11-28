package group

// Scalar interface abstracts common operations on scalars in a Group.
type Scalar interface {
	// Random sets the current scalar to a new random scalar and returns it.
	Random() Scalar

	// Add adds the argument to the receiver, sets the receiver to the result and returns it.
	Add(scalar Scalar) Scalar

	// Sub subtracts the argument from the receiver, sets the receiver to the result and returns it.
	Sub(scalar Scalar) Scalar

	// Mult multiplies the argument with the receiver, sets the receiver to the result and returns it.
	Mult(scalar Scalar) Scalar

	// Invert returns the scalar's modular inverse ( 1 / scalar ).
	Invert() Scalar

	// Copy returns a copy of the Scalar.
	Copy() Scalar

	// Decode decodes the input an sets the current scalar to its value, and returns it.
	Decode(in []byte) (Scalar, error)

	// Bytes returns the byte encoding of the element.
	Bytes() []byte
}
