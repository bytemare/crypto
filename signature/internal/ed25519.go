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
		pk: make([]byte, ed25519.PublicKeySize),
	}
}

func (ed *Ed25519) extractPublicKey() {
	if ed.sk == nil {
		panic("Ed25519 private key is not set")
	}

	copy(ed.pk, ed.sk[ed25519.PublicKeySize:])
}

func (ed *Ed25519) setKeys(sk []byte) {
	ed.sk = sk
	ed.extractPublicKey()
}

// LoadKey loads the given key. Will not fail if the key is invalid, but it might later.
func (ed *Ed25519) LoadKey(privateKey []byte) {
	if len(privateKey) != ed25519.PrivateKeySize {
		panic("Ed25519 invalid private key size")
	}

	ed.setKeys(privateKey)
}

// GenerateKey generates a fresh signing key and stores it in ed.
func (ed *Ed25519) GenerateKey() error {
	var err error
	_, ed.sk, err = ed25519.GenerateKey(nil)

	return err
}

// GetPrivateKey returns the private key's seed, reducing by half the needed storage.
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

// Seed re-calculates the private key from the seed for compatible schemes. Implementations can only retain a seed
// to reduce storage size.
func (ed *Ed25519) Seed(seed []byte) {
	ed.setKeys(ed25519.NewKeyFromSeed(seed))
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
