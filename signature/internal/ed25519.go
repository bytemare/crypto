package internal

import (
	"crypto"
	"crypto/ed25519"
	"io"

	"github.com/bytemare/cryptotools/utils"
)

// Ed25519 implements the Signature interfaces and wraps crypto/ed22519.
type Ed25519 struct {
	sk ed25519.PrivateKey
	pk ed25519.PublicKey
}

// NewEd25519 returns an empty Ed25519 structure.
func NewEd25519() *Ed25519 {
	return &Ed25519{
		sk: nil,
		pk: nil,
	}
}

// SetPrivateKey loads the given private key and sets the public key accordingly.
func (ed *Ed25519) SetPrivateKey(privateKey []byte) {
	if len(privateKey) != ed25519.SeedSize {
		panic("Ed25519 invalid private key size")
	}

	ed.sk = ed25519.NewKeyFromSeed(privateKey)
	ed.pk = make([]byte, ed25519.PublicKeySize)
	copy(ed.pk, ed.sk[ed25519.PublicKeySize:])
}

// GenerateKey generates a fresh private/public key pair and stores it in ed.
func (ed *Ed25519) GenerateKey() {
	seed := utils.RandomBytes(ed25519.SeedSize)
	ed.SetPrivateKey(seed)
}

// GetPrivateKey returns the private key (without the public key part).
func (ed *Ed25519) GetPrivateKey() []byte {
	return ed.sk.Seed()
}

// GetPublicKey returns the public key.
func (ed *Ed25519) GetPublicKey() []byte {
	return ed.pk
}

// Public implements the Signer.Public() function.
func (ed *Ed25519) Public() crypto.PublicKey {
	return crypto.PublicKey(ed.pk)
}

// SignMessage uses the private key in ed to sign the input. The input doesn't need to be hashed beforehand.
func (ed *Ed25519) SignMessage(message ...[]byte) []byte {
	m := utils.Concatenate(0, message...)
	return ed25519.Sign(ed.sk, m)
}

// Sign implements the Signer.Sign() function.
func (ed *Ed25519) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	return ed.sk.Sign(rand, digest, opts)
}

// Verify checks whether signature of the message is valid given the public key.
func (ed *Ed25519) Verify(publicKey, message, signature []byte) bool {
	return ed25519.Verify(publicKey, message, signature)
}
