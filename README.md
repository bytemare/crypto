# Prime-order Elliptic Curve Groups
[![CI](https://github.com/bytemare/crypto/actions/workflows/ci.yml/badge.svg)](https://github.com/bytemare/crypto/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/bytemare/crypto.svg)](https://pkg.go.dev/github.com/bytemare/crypto)
[![codecov](https://codecov.io/gh/bytemare/crypto/branch/main/graph/badge.svg?token=5bQfB0OctA)](https://codecov.io/gh/bytemare/crypto)

```Go
  import "github.com/bytemare/crypto"
```

This package exposes abstract operations over opaque prime-order elliptic curve groups and their scalars and elements,
and implements the latest [hash-to-curve](https://datatracker.ietf.org/doc/draft-irtf-cfrg-hash-to-curve) specification
to date.

It is made so you can swap between primitives with no code change. The only changing parameter is the Group identifier.
The package serves as an interface to optimized and secured implementations that serve as backends, and to which you
don't need to adapt.

The following table indexes supported groups with hash-to-curve capability and links each one to the underlying implementations:

| ID  | Name         | Backend                       |
|-----|--------------|-------------------------------|
| 1   | Ristretto255 | github.com/gtank/ristretto255 |
| 2   | Decaf448     | not yet supported             |
| 3   | P-256        | filippo.io/nistec             |
| 4   | P-384        | filippo.io/nistec             |
| 5   | P-521        | filippo.io/nistec             |
| 6   | Edwards25519 | filippo.io/edwards25519       |
| 7   | Secp256k1    | github.com/bytemare/crypto    |
| 8   | Double-Odd   | not yet supported             |

## Prime-order group interface

This package defines an interface to the group and its scalars and elements, but exposes a type that handles that for
you. You don't need to instantiate or implement anything.

### Group interface

```Go
// Group abstracts operations in a prime-order group.
type Group interface {
    NewScalar() Scalar
    NewElement() Element
    Base() Element
    HashToScalar(input, dst []byte) Scalar
    HashToGroup(input, dst []byte) Element
    EncodeToGroup(input, dst []byte) Element
    Ciphersuite() string
    ScalarLength() int
    ElementLength() int
    Order() string
}
```

### Scalar interface

```Go
// Scalar interface abstracts common operations on scalars in a prime-order Group.
type Scalar interface {
    Zero() Scalar
    One() Scalar
    Random() Scalar
    Add(Scalar) Scalar
    Subtract(Scalar) Scalar
    Multiply(Scalar) Scalar
    Pow(Scalar) Scalar
    Invert() Scalar
    Equal(Scalar) int
    LessOrEqual(Scalar) int
    IsZero() bool
    Set(Scalar) Scalar
    SetInt(big.Int) error
    Copy() Scalar
    Encode() []byte
    Decode(in []byte) error
    encoding.BinaryMarshaler
    encoding.BinaryUnmarshaler
}
```

### Element interface
```Go
// Element interface abstracts common operations on an Element in a prime-order Group.
type Element interface {
    Base() Element
    Identity() Element
    Add(Element) Element
    Double() Element
    Negate() Element
    Subtract(Element) Element
    Multiply(Scalar) Element
    Equal(element Element) int
    IsIdentity() bool
    Set(Element) Element
    Copy() Element
    Encode() []byte
    XCoordinate() []byte
    Decode(data []byte) error
    encoding.BinaryMarshaler
    encoding.BinaryUnmarshaler
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
