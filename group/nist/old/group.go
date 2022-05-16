package internal

import (
	"crypto"
	"crypto/elliptic"
	"filippo.io/nistec"
	"math/big"
	"sync"

	"github.com/bytemare/crypto/group/hash2curve"
)

var (
	initOnceP256 sync.Once
	initOnceP384 sync.Once
	initOnceP521 sync.Once

	p256 *Group
	p384 *Group
	p521 *Group
)

func P256() *Group {
	initOnceP256.Do(initP256)
	return p256
}

func P384() *Group {
	initOnceP384.Do(initP384)
	return p384
}

func P521() *Group {
	initOnceP521.Do(initP521)
	return p521
}

func initP256() {
	p256 = new(Group)
	setGroupParams(p256,
		"0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
		"0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
		"0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
	)
	setCurveParams(&p256.curve, elliptic.P256,
		"115792089210356248762697446949407573530086143415290314195533631308867097853951",
		"0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
	)
	setMapping(&p256.curve, crypto.SHA256, "-10", 48)
}

func initP384() {
	p384 = new(Group)
	setGroupParams(p384,
		"0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973",
		"0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7",
		"0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f",
	)
	setCurveParams(
		&p384.curve,
		elliptic.P384,
		"39402006196394479212279040100143613805079739270465446667948293404245721771496870329047266088258938001861606973112319",
		"0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef",
	)
	setMapping(&p384.curve, crypto.SHA384, "-12", 72)
}

func initP521() {
	p521 = new(Group)
	setGroupParams(
		p521,
		"0x1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409",
		"0xc6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66",
		"0x11839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650",
	)
	setCurveParams(
		&p521.curve,
		elliptic.P521,
		"6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057151",
		"0x051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00",
	)
	setMapping(&p521.curve, crypto.SHA512, "-4", 98)
}

func setGroupParams(g *Group, order, gx, gy string) {
	g.scalarField = NewField(s2int(order))
	g.gx = s2int(gx)
	g.gy = s2int(gy)
}

// Group represents a group over a NIST curve. It exposes a prime-order group API with hash-to-curve operations.
type Group struct {
	curve       Curve
	scalarField *field
	gx, gy      *big.Int
	newPoint    func() NistECPoint[any]
	newScalar   func() *Scalar
}

// NewScalar returns a new, empty, scalar.
func (g Group) NewScalar() *Scalar {
	return NewScalar(g)
}

// PointLength returns the byte size of an encoded element.
func (g Group) PointLength() uint {
	return pointLen(g.curve.field.BitLen())
}

func (g Group) newP256Point() *Element[*nistec.P256Point] {
	e := &Element[*nistec.P256Point]{
		p:     nistec.NewP256Point(),
		group: g,
	}
	e.group.newPoint = nistec.NewP256Point
}

func (g Group) newP384Point() *Element[*nistec.P384Point] {
	return &Element[*nistec.P384Point]{p: nistec.NewP384Point(), newPoint: nistec.NewP384Point}
}

func (g Group) newP521Point() *Element[*nistec.P521Point] {
	return &Element[*nistec.P521Point]{p: nistec.NewP521Point(), newPoint: nistec.NewP521Point}
}

// NewPoint returns the identity point (point at infinity).
func (g Group) NewPoint() *Point {
	return g.curve.identity()
}

// HashToGroup allows arbitrary input to be safely mapped to the curve of the group.
func (g Group) HashToGroup(input, dst []byte) *Point {
	return g.curve.hashXMD(input, dst)
}

// EncodeToGroup allows arbitrary input to be mapped non-uniformly to points in the Group.
func (g Group) EncodeToGroup(input, dst []byte) *Point {
	return g.curve.encodeXMD(input, dst)
}

// HashToScalar allows arbitrary input to be safely mapped to the field.
func (g Group) HashToScalar(input, dst []byte) *Scalar {
	s := hash2curve.HashToFieldXMD(g.curve.hash, input, dst, 1, 1, g.curve.secLength, g.scalarField.prime)[0]

	// If necessary, build a buffer of right size, so it gets correctly interpreted.
	b := s.Bytes()
	length := (g.curve.field.BitLen() + 7) / 8
	if l := length - len(b); l > 0 {
		buf := make([]byte, l, length)
		buf = append(buf, b...)
		b = buf
	}

	return &Scalar{
		s: new(big.Int).SetBytes(b),
		f: g.curve.field,
	}
}

// Base returns group's base point a.k.a. canonical generator.
func (g Group) Base() *Point {
	return &Point{
		curve: &g.curve,
		x:     g.gx,
		y:     g.gy,
	}
}

// MultBytes allows []byte encodings of a scalar and an element of the group to be multiplied.
func (g Group) MultBytes(s, e []byte) (*Point, error) {
	sc, err := g.NewScalar().Decode(s)
	if err != nil {
		return nil, err
	}

	e1, err := g.NewPoint().Decode(e)
	if err != nil {
		return nil, err
	}

	return g.NewPoint().Mult(sc, e1), nil
}
