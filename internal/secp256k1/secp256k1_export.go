package secp256k1

import (
	"encoding/hex"
	"log"
	"testing"
)

/*
	This file exports the testing function to enable usage of internal functions without the need to export them.
	See secp256k1_test.go to run them.

	The Magma code from is copied here with some testing input and its output values:

```
order := 115792089237316195423570985008687907853269984665640564039457584007908834671663;
baseX := 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798;
baseY := 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8;
baseZ := 1;
b := 7;
b3 := 21;

ADD := function ( X1 , Y1 , Z1 , X2 , Y2 , Z2 , b3 )
t0 := X1 * X2 ; t1 := Y1 * Y2 ; t2 := Z1 * Z2 ;
t3 := X1 + Y1 ; t4 := X2 + Y2 ; t3 := t3 * t4 ;
t4 := t0 + t1 ; t3 := t3 - t4 ; t4 := Y1 + Z1 ;
X3 := Y2 + Z2 ; t4 := t4 * X3 ; X3 := t1 + t2 ;
t4 := t4 - X3 ; X3 := X1 + Z1 ; Y3 := X2 + Z2 ;
X3 := X3 * Y3 ; Y3 := t0 + t2 ; Y3 := X3 - Y3 ;
X3 := t0 + t0 ; t0 := X3 + t0 ; t2 := b3 * t2 ;
Z3 := t1 + t2 ; t1 := t1 - t2 ; Y3 := b3 * Y3 ;
X3 := t4 * Y3 ; t2 := t3 * t1 ; X3 := t2 - X3 ;
Y3 := Y3 * t0 ; t1 := t1 * Z3 ; Y3 := t1 + Y3 ;
t0 := t0 * t3 ; Z3 := Z3 * t4 ; Z3 := Z3 + t0 ;
return X3 mod order, Y3 mod order, Z3 mod order;
end function ;

DBL := function (X ,Y ,Z , b3 )
t0 := Y ^2; Z3 := t0 + t0 ; Z3 := Z3 + Z3 ;
Z3 := Z3 + Z3 ; t1 := Y * Z ; t2 := Z ^2;
t2 := b3 * t2 ; X3 := t2 * Z3 ; Y3 := t0 + t2 ;
Z3 := t1 * Z3 ; t1 := t2 + t2 ; t2 := t1 + t2 ;
t0 := t0 - t2 ; Y3 := t0 * Y3 ; Y3 := X3 + Y3 ;
t1 := X * Y ; X3 := t0 * t1 ; X3 := X3 + X3 ;
return X3 mod order, Y3 mod order, Z3 mod order;
end function ;

print "base + base";
x, y, z := ADD(baseX , baseY, baseZ, baseX , baseY, baseZ, b3);
print "x: ", x:Hex;
print "y: ", y:Hex;
print "z: ", z:Hex;

print "";

print "double(base)";
x, y, z := DBL (baseX , baseY, baseZ, b3);
print "x: ", x:Hex;
print "y: ", y:Hex;
print "z: ", z:Hex;
```

Output:
base + base
x:  0xF40AF3B6C6FDF9AA5402B9FDC39AC4B67827EB373C92077452348E044F109FC8
y:  0x56915849F52CC8F76F5FD7E4BF60DB4A43BF633E1B1383F85FE89164BFADCBDB
z:  0xF8783C53DFB2A307B568A6AD931FC97023DC71CDC3EAC498B0C6BA5554759A29

double(base)
x:  0xF40AF3B6C6FDF9AA5402B9FDC39AC4B67827EB373C92077452348E044F109FC8
y:  0x56915849F52CC8F76F5FD7E4BF60DB4A43BF633E1B1383F85FE89164BFADCBDB
z:  0xF8783C53DFB2A307B568A6AD931FC97023DC71CDC3EAC498B0C6BA5554759A29



*/

const (
	/*
		These values come from
		https://github.com/cfrg/draft-irtf-cfrg-frost/blob/master/poc/frost-secp256k1-sha256.json#L11-L12
	*/
	frostPubkeyHex    = "02f37c34b66ced1fb51c34a90bdae006901f10625cc06c4f64663b0eae87d87b4f"
	frostSecretKeyHex = "0d004150d27c3bf2a42f312683d35fac7394b1e9e318249c1bfe7f0795a83114"
)

var secp256k1 = Group{}

func hexToBytes(t *testing.T, in string) []byte {
	bytes, err := hex.DecodeString(in)
	if err != nil {
		t.Fatal(err)
	}

	return bytes
}

func hexToScalar(t *testing.T, in string) *Scalar {
	bytes := hexToBytes(t, in)

	s := newScalar()
	if err := s.decode(bytes); err != nil {
		t.Fatal(err)
	}

	return s
}

func hexToElement(t *testing.T, in string) *Element {
	bytes := hexToBytes(t, in)

	e := newElement()
	if err := e.decode(bytes); err != nil {
		t.Fatal(err)
	}

	return e
}

func basePoint() *Element {
	e := newElement()
	e.x.Set(baseX)
	e.y.Set(baseY)
	e.z.Set(scOne)

	return e
}

func (e *Element) printAffine() {
	x, y := e.affine()
	log.Printf("Affine coordinates")
	log.Printf("\tx: %s", hex.EncodeToString(x.Bytes()))
	log.Printf("\ty: %s", hex.EncodeToString(y.Bytes()))
}

func (e *Element) printJacobian() {
	log.Printf("Jacobian coordinates")
	log.Printf("\tx: %s", hex.EncodeToString(e.x.Bytes()))
	log.Printf("\ty: %s", hex.EncodeToString(e.y.Bytes()))
	log.Printf("\tz: %s", hex.EncodeToString(e.z.Bytes()))
}

func PrintOutputs() {
	base := basePoint()
	log.Printf("Base point")
	base.printAffine()
	base.printJacobian()

	log.Println()

	// Incomplete
	formulaType = incomplete // This will switch using the incomplete formula

	incompleteAdd := basePoint()
	incompleteAdd.add(basePoint()) // = 2 * base
	incompleteAdd.add(basePoint()) // = 3 * base
	log.Printf("Incomplete Jacobian 2*base+base")
	incompleteAdd.printAffine()
	incompleteAdd.printJacobian()

	log.Println()

	// Complete
	formulaType = complete // This will switch using the complete formula

	completeAdd := basePoint()
	completeAdd.add(basePoint()) // = 2 * base
	completeAdd.add(basePoint()) // = 3 * base
	log.Printf("Complete Jacobian 2*base+base")
	completeAdd.printAffine()
	completeAdd.printJacobian()
}

func ScalarMultFrost(t *testing.T) {
	frostSk := hexToScalar(t, frostSecretKeyHex)
	frostPk := hexToElement(t, frostPubkeyHex)
	log.Printf("Reference public key from FROST")
	frostPk.printAffine()
	frostPk.printJacobian()

	log.Println()

	// Incomplete
	log.Printf("ScalarMult with incomplete formulae")
	formulaType = incomplete // This will switch using the incomplete formula

	base := basePoint()
	pk := base.multiply(frostSk)
	log.Printf("Same output? %v", pk.Equal(frostPk) == 1)
	log.Printf("Our base*sk")
	pk.printAffine()
	pk.printJacobian()

	log.Println()

	// Complete
	log.Printf("ScalarMult with complete formulae")
	formulaType = complete // This will switch using the complete formula

	base = basePoint()
	pk = base.multiply(frostSk)
	log.Printf("Same output? %v", pk.Equal(frostPk) == 1)
	log.Printf("Our base*sk")
	pk.printAffine()
	pk.printJacobian()
}

func AddJacobianComplete() {
	formulaType = complete
	base := basePoint()
	base.add(base)
	log.Printf("Base + base with complete formula")
	base.printAffine()
	base.printJacobian()
}

func Double() {
	formulaType = incomplete
	base := basePoint()
	base.double()
	log.Printf("double(base) with incomplete formula")
	base.printAffine()
	base.printJacobian()

	log.Println()

	formulaType = complete
	base = basePoint()
	base.double()
	log.Printf("double(base) with complete formula")
	base.printAffine()
	base.printJacobian()
}
