# Prime-order Elliptic Curve Groups
[![CI](https://github.com/bytemare/crypto/actions/workflows/ci.yml/badge.svg)](https://github.com/bytemare/crypto/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/bytemare/crypto.svg)](https://pkg.go.dev/github.com/bytemare/crypto)
[![codecov](https://codecov.io/gh/bytemare/crypto/branch/main/graph/badge.svg?token=5bQfB0OctA)](https://codecov.io/gh/bytemare/crypto)

```Go
  import "github.com/bytemare/crypto"
```

This package exposes abstract operations over opaque prime-order elliptic curve groups and their scalars and elements,
and implements the latest [hash-to-curve](https://datatracker.ietf.org/doc/draft-irtf-cfrg-hash-to-curve/) specification
to date.

It is made so you can swap between primitives with no code change. The only changing parameter is the Group identifier.
The package serves as an interface to optimized and secured implementations that serve as backends, and to which you
don't need to adapt.

The following table indexes supported groups with hash-to-curve capability and links each one to the underlying implementations:

| ID  | Name         | Implementation                |
|-----|--------------|-------------------------------|
| 1   | Ristretto255 | github.com/gtank/ristretto255 |
| 2   | Decaf448     | not yet supported             |
| 3   | P-256        | filippo.io/nistec             |
| 4   | P-384        | filippo.io/nistec             |
| 5   | P-521        | filippo.io/nistec             |
| 6   | Edwards25519 | filippo.io/edwards25519       |
| 7   | Edwards448   | not yet supported             |

## Prime-order group interface

This package defines an interface to the group and its scalars and elements, but exposes a type that handles that for
you. You don't need to instantiate or implement anything.

### Group interface

```Go
// Group abstracts operations in a prime-order group.
type Group interface {
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

	// Ciphersuite returns the hash-to-curve ciphersuite identifier.
	Ciphersuite() string
}
```

### Scalar interface

```Go
// Scalar interface abstracts common operations on scalars in a prime-order Group.
type Scalar interface {
    // Random sets the current scalar to a new random scalar and returns it.
    Random() Scalar

	// Add returns the sum of the scalars, and does not change the receiver.
	Add(scalar Scalar) Scalar

	// Subtract returns the difference between the scalars, and does not change the receiver.
	Subtract(scalar Scalar) Scalar

	// Multiply returns the multiplication of the scalars, and does not change the receiver.
	Multiply(scalar Scalar) Scalar

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

	// Equal returns 1 if the scalars are equal, and 0 otherwise.
	Equal(scalar Scalar) int

	// Zero sets the scalar to 0, and returns it.
	Zero() Scalar
}
```

```Go
### Element interface
// Element interface abstracts common operations on an Element in a prime-order Group.
type Element interface {
    // Add returns the sum of the Elements, and does not change the receiver.
    Add(Element) Element

	// Subtract returns the difference between the Elements, and does not change the receiver.
	Subtract(Element) Element

	// Multiply returns the scalar multiplication of the receiver with the given Scalar,
	// and does not change the receiver.
	Multiply(Scalar) Element

	// IsIdentity returns whether the Element is the point at infinity of the Group's underlying curve.
	IsIdentity() bool

	// Copy returns a copy of the Element.
	Copy() Element

	// Decode decodes the input a sets the receiver to its value, and returns it.
	Decode(in []byte) (Element, error)

	// Bytes returns the compressed byte encoding of the point.
	Bytes() []byte

	// Double returns the double of the element, and does not change the receiver.
	Double() Element

	// Base sets the element to the group's base point a.k.a. canonical generator.
	Base() Element

	// Identity sets the element to the point at infinity of the Group's underlying curve.
	Identity() Element

	// Equal returns 1 if the elements are equivalent, and 0 otherwise.
	Equal(element Element) int

	// Negate returns the negative of the Element, and does not change the receiver.
	Negate() Element
}
```

## Documentation [![Go Reference](https://pkg.go.dev/badge/github.com/bytemare/crypto.svg)](https://pkg.go.dev/github.com/bytemare/crypto)

You can find the documentation and usage examples in [the package doc](https://pkg.go.dev/github.com/bytemare/crypto) and [the project wiki](https://github.com/bytemare/crypto/wiki) .

## Versioning

[SemVer](http://semver.org) is used for versioning. For the versions available, see the [tags on the repository](https://github.com/bytemare/crypto/tags).

## Contributing

Please read [CONTRIBUTING.md](.github/CONTRIBUTING.md) for details on the code of conduct, and the process for submitting pull requests.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.