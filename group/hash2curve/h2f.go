package hash2curve

import (
	"crypto"
	"math/big"

	"github.com/bytemare/crypto/group/internal"
	"github.com/bytemare/crypto/hash"
)

func HashToFieldXOF(id hash.Extendable, input, dst []byte, count, ext, securityLength int, modulo *big.Int) []*big.Int {
	expLength := count * ext * securityLength // elements * ext * security length
	uniform := ExpandXOF(id, input, dst, expLength)

	res := make([]*big.Int, count)
	for i := 0; i < count; i++ {
		offset := i * securityLength
		res[i] = reduce(uniform[offset:offset+securityLength], modulo)
	}

	return res
}

func HashToFieldXMD(id crypto.Hash, input, dst []byte, count, ext, securityLength int, modulo *big.Int) []*big.Int {
	expLength := count * ext * securityLength // elements * ext * security length
	uniform := ExpandXMD(id, input, dst, expLength)

	res := make([]*big.Int, count)
	for i := 0; i < count; i++ {
		offset := i * securityLength
		res[i] = reduce(uniform[offset:offset+securityLength], modulo)
	}

	return res
}

func reduce(input []byte, modulo *big.Int) *big.Int {
	/*
		Interpret the input as a big-endian encoded unsigned integer of the field, and reduce it modulo the prime.
	*/
	i := new(big.Int).SetBytes(input)
	i.Mod(i, modulo)

	// If necessary, build a buffer of right size, so it gets correctly interpreted.
	//b := i.Bytes()
	//if l := length - len(b); l > 0 {
	//	buf := make([]byte, l, length)
	//	buf = append(buf, b...)
	//	b = buf
	//}

	return i
}

// Elligator2Montgomery implements the Elligator2 mapping to Curve25519.
func Elligator2Montgomery(e, a internal.FieldElement, f internal.Field) (x, y internal.FieldElement) {
	t1 := f.New().Square(e)        // u^2
	t1.Multiply(t1, f.Two())       // t1 = 2u^2
	e1 := t1.IsEqual(f.MinusOne()) //
	t1.Swap(f.Zero(), e1)          // if 2u^2 == -1, t1 = 0

	x1 := f.New().Add(t1, f.One())     // t1 + 1
	x1.Invert(x1)                      // 1 / (t1 + 1)
	x1.Multiply(x1, f.New().Negate(a)) // x1 = -A / (t1 + 1)

	gx1 := f.New().Add(x1, a) // x1 + A
	gx1.Multiply(gx1, x1)     // x1 * (x1 + A)
	gx1.Add(gx1, f.One())     // x1 * (x1 + A) + 1
	gx1.Multiply(gx1, x1)     // x1 * (x1 * (x1 + A) + 1)

	x2 := f.New().Negate(x1) // -x1
	x2.Subtract(x2, a)       // -x2 - A

	gx2 := f.New().Multiply(t1, gx1) // t1 * gx1

	root1, _isSquare := f.New().SqrtRatio(gx1, f.One()) // root1 = (+) sqrt(gx1)
	negRoot1 := f.New().Negate(root1)                   // negRoot1 = (-) sqrt(gx1)
	root2, _ := f.New().SqrtRatio(gx2, f.One())         // root2 = (+) sqrt(gx2)

	// if gx1 is square, set the point to (x1, -root1)
	// if not, set the point to (x2, +root2)
	if _isSquare == 1 {
		x = x1
		y = negRoot1 // set sgn0(y) == 1, i.e. negative
	} else {
		x = x2
		y = root2 // set sgn0(y) == 0, i.e. positive
	}

	return x, y
}

// MontgomeryToEdwards lifts a Curve25519 point to its Edwards25519 equivalent.
func MontgomeryToEdwards(u, v, invsqrtD internal.FieldElement, f internal.Field) (x, y internal.FieldElement) {
	x = f.New().Invert(v)
	x.Multiply(x, u)
	x.Multiply(x, invsqrtD)

	y = MontgomeryUToEdwardsY(u, f)

	return
}

// MontgomeryUToEdwardsY transforms a Curve25519 x (or u) coordinate to an Edwards25519 y coordinate.
func MontgomeryUToEdwardsY(u internal.FieldElement, f internal.Field) internal.FieldElement {
	u1 := f.New().Subtract(u, f.One())
	u2 := f.New().Add(u, f.One())

	return u1.Multiply(u1, u2.Invert(u2))
}
