package secp256k1_test

import (
	"github.com/bytemare/crypto/internal/secp256k1"
	"testing"
)

/*
	To trigger these tests, execute `go test` in this directory.
*/

func TestAddAffineBaseX3(t *testing.T) {
	secp256k1.AddAffineBaseX3()
}

func TestTest(t *testing.T) {
	secp256k1.Basex3()
}

func TestScalarMult(t *testing.T) {
	secp256k1.ScalarMultFrost(t)
}

func TestAddJacobianComplete(t *testing.T) {
	secp256k1.AddJacobianComplete()
}

func TestDouble(t *testing.T) {
	secp256k1.Double()
}
