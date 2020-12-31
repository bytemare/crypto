package group

// Scalar interface abstracts common operations on scalars in a Group.
type Scalar interface {
	// Random sets the current scalar to a new random scalar and returns it.
	Random() Scalar

	// Add returns the sum of the scalars, and does not change the receiver.
	Add(scalar Scalar) Scalar

	// Sub returns the difference between the scalars, and does not change the receiver.
	Sub(scalar Scalar) Scalar

	// Mult returns the multiplication of the scalars, and does not change the receiver.
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
