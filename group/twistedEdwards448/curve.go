package twistedEdwards448

import (
	"crypto/subtle"
	"github.com/bytemare/crypto/group/hash2curve"
	fp "github.com/bytemare/crypto/group/twistedEdwards448/field"
	"github.com/bytemare/crypto/hash"
	"math/big"
	"math/bits"
)

var (
	// genX is the x-coordinate of the generator of ted448 curve.
	genX = fp.Elt{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x80, 0xfe, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
	}
	// genY is the y-coordinate of the generator of ted448 curve.
	genY = fp.Elt{
		0x64, 0x4a, 0xdd, 0xdf, 0xb4, 0x79, 0x60, 0xc8,
		0xa1, 0x70, 0xb4, 0x3a, 0x1e, 0x0c, 0x9b, 0x19,
		0xe5, 0x48, 0x3f, 0xd7, 0x44, 0x18, 0x18, 0x14,
		0x14, 0x27, 0x45, 0x50, 0x2c, 0x24, 0xd5, 0x93,
		0xc3, 0x74, 0x4c, 0x50, 0x70, 0x43, 0x26, 0x05,
		0x08, 0x24, 0xca, 0x78, 0x30, 0xc1, 0x06, 0x8d,
		0xd4, 0x86, 0x42, 0xf0, 0x14, 0xde, 0x08, 0x85,
	}
	// paramD is -39082 in Fp. The D parameter of the ted448 curve.
	paramD = fp.Elt{
		0x55, 0x67, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	}
	// order is 2^446-0x8335dc163bb124b65129c96fde933d8d723a70aadc873d6d54a7bb0d,
	// which is the number of points in the prime subgroup.
	order = Scalar{ // little-endian
		0xf3, 0x44, 0x58, 0xab, 0x92, 0xc2, 0x78, 0x23,
		0x55, 0x8f, 0xc5, 0x8d, 0x72, 0xc2, 0x6c, 0x21,
		0x90, 0x36, 0xd6, 0xae, 0x49, 0xdb, 0x4e, 0xc4,
		0xe9, 0x23, 0xca, 0x7c, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3f,
	}
	// residue448 is 2^448 mod order.
	residue448 = [4]uint64{
		0x721cf5b5529eec34, 0x7a4cf635c8e9c2ab, 0xeec492d944a725bf, 0x20cd77058,
	}
)

// ScalarBaseMult calculates R = kG, where G is the generator point.
func ScalarBaseMult(k *Scalar) *Point {
	g := Generator()
	return ScalarMult(k, &g)
}

// Identity returns the identity point.
func Identity() Point { return Point{Y: fp.One(), Z: fp.One()} }

// Generator returns the generator point.
func Generator() Point { return Point{X: genX, Y: genY, Z: fp.One(), Ta: genX, Tb: genY} }

// Order returns the number of points in the prime subgroup in little-endian order.
func Order() (r [ScalarSize]byte) { r = order; return r }

// IsOnCurve returns true if the point lies on the curve.
func IsOnCurve(P *Point) bool {
	eq0 := fp.IsZero(&P.X)
	eq0 &= fp.IsZero(&P.Y)
	eq0 &= fp.IsZero(&P.Z)
	eq0 &= fp.IsZero(&P.Ta)
	eq0 &= fp.IsZero(&P.Tb)
	eq0 = 1 - eq0
	x2, y2, t, t2, z2 := &fp.Elt{}, &fp.Elt{}, &fp.Elt{}, &fp.Elt{}, &fp.Elt{}
	rhs, lhs := &fp.Elt{}, &fp.Elt{}
	fp.Mul(t, &P.Ta, &P.Tb)  // t = ta*tb
	fp.Square(x2, &P.X)      // x^2
	fp.Square(y2, &P.Y)      // y^2
	fp.Square(z2, &P.Z)      // z^2
	fp.Square(t2, t)         // t^2
	fp.Sub(lhs, y2, x2)      // -x^2 + y^2, since a=-1
	fp.Mul(rhs, t2, &paramD) // dt^2
	fp.Add(rhs, rhs, z2)     // z^2 + dt^2
	fp.Sub(lhs, lhs, rhs)    // ax^2 + y^2 - (z^2 + dt^2)
	eq1 := fp.IsZero(lhs)
	fp.Mul(lhs, &P.X, &P.Y) // xy
	fp.Mul(rhs, t, &P.Z)    // tz
	fp.Sub(lhs, lhs, rhs)   // xy - tz
	eq2 := fp.IsZero(lhs)
	return subtle.ConstantTimeByteEq(byte(4*eq2+2*eq1+eq0), 0x7) == 1
}

// subYDiv16 update x = (x - y) / 16.
func subYDiv16(x *scalar64, y int64) {
	s := uint64(y >> 63)
	x0, b0 := bits.Sub64((*x)[0], uint64(y), 0)
	x1, b1 := bits.Sub64((*x)[1], s, b0)
	x2, b2 := bits.Sub64((*x)[2], s, b1)
	x3, b3 := bits.Sub64((*x)[3], s, b2)
	x4, b4 := bits.Sub64((*x)[4], s, b3)
	x5, b5 := bits.Sub64((*x)[5], s, b4)
	x6, _ := bits.Sub64((*x)[6], s, b5)
	x[0] = (x0 >> 4) | (x1 << 60)
	x[1] = (x1 >> 4) | (x2 << 60)
	x[2] = (x2 >> 4) | (x3 << 60)
	x[3] = (x3 >> 4) | (x4 << 60)
	x[4] = (x4 >> 4) | (x5 << 60)
	x[5] = (x5 >> 4) | (x6 << 60)
	x[6] = x6 >> 4
}

func recodeScalar(d *[113]int8, k *scalar64) {
	for i := 0; i < 112; i++ {
		d[i] = int8((k[0] & 0x1f) - 16)
		subYDiv16(k, int64(d[i]))
	}
	d[112] = int8(k[0])
}

var fieldPrime, _ = new(big.Int).SetString("7268387242956068905493238078880045343536413606873180602814901991806"+
	"12328166730772686396383698676545930088884461843637361053498018365439", 10)

func adjust(in []byte, length int) []byte {
	// If necessary, build a buffer of right size, so it gets correctly interpreted.
	if l := length - len(in); l > 0 {
		buf := make([]byte, l, length)
		buf = append(buf, in...)
		in = buf
	}

	// Reverse, because filippo.io/edwards25519 works in little-endian
	return reverse(in)
}

func reverse(b []byte) []byte {
	l := len(b) - 1
	for i := 0; i < len(b)/2; i++ {
		b[i], b[l-i] = b[l-i], b[i]
	}

	return b
}

func HashToGroup(input, dst []byte) *Point {
	u := hash2curve.HashToFieldXOF(hash.SHAKE256, input, dst, 2, 1, 224, fieldPrime)
	q0 := adjust(u[0].Bytes(), 56)
	q1 := adjust(u[1].Bytes(), 56)
	p0 := MapToEdwards(q0)
	p1 := MapToEdwards(q1)
	p0.Add(p0, p1)
	p0.MultByCofactor(p0)

	return p0
}

// ScalarMult calculates R = kP.
func ScalarMult(k *Scalar, P *Point) *Point {
	var TabP [8]prePointProy
	var S prePointProy
	var d [113]int8

	var k64, _k64, order64 scalar64
	k64.fromScalar(k)
	order64.fromScalar(&order)
	k64.cmov(&order64, uint64(k64.isZero()))

	isEven := 1 - int(k64[0]&0x1)
	_k64.sub(&order64, &k64)
	k64.cmov(&_k64, uint64(isEven))

	recodeScalar(&d, &k64)

	P.oddMultiples(TabP[:])
	Q := Identity()
	for i := 112; i >= 0; i-- {
		Q.Double()
		Q.Double()
		Q.Double()
		Q.Double()
		mask := d[i] >> 7
		absDi := (d[i] + mask) ^ mask
		inx := int32((absDi - 1) >> 1)
		sig := int((d[i] >> 7) & 0x1)
		for j := range TabP {
			S.cmov(&TabP[j], uint(subtle.ConstantTimeEq(inx, int32(j))))
		}
		S.cneg(sig)
		Q.mixAdd(&S)
	}
	Q.cneg(uint(isEven))

	return &Q
}
