package group

import (
	"fmt"
	"github.com/bytemare/crypto"
	"testing"
)

func TestSecAdd(t *testing.T) {
	g := crypto.Secp256k1

	base2 := g.Base().Add(g.Base())
	fmt.Printf("2x Base\n")
	fmt.Printf("\t> %v\n", base2.Encode())

	base3 := base2.Add(g.Base())
	fmt.Printf("3x Base\n")
	fmt.Printf("\t> %v\n", base3.Encode())
}

func TestSecDouble(t *testing.T) {
	g := crypto.Secp256k1

	double := g.Base().Double()
	fmt.Printf("Double\n\t> %v\n", double.Encode())
}