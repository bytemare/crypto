package cryptotools

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/bytemare/cryptotools/hash"
	"github.com/bytemare/cryptotools/hashtogroup"
	"github.com/bytemare/cryptotools/ihf"
)

var (
	shortDST = []byte("shortDST")
	normalDST = []byte("CryptoTools-Test00")
)

func TestPatchCiphersuite(t *testing.T) {
	defaultCSP := &Parameters{
		Group:  defGroup,
		Hash:   defHash,
		IHF:    defIHF,
		IHFLen: defIHFLen,
	}

	emptyCSP := &Parameters{}

	// Test Nil
	csp, err := patchCipherSuite(nil)
	if err != nil {
		t.Error(err)
	} else {
		assert.EqualValues(t, defaultCSP, csp)
	}

	// Test empty
	csp, err = patchCipherSuite(emptyCSP)
	if err != nil {
		t.Error(err)
	} else {
		assert.EqualValues(t, defaultCSP, csp)
	}

	// Test Invalid values
	var invalidGroup hashtogroup.Ciphersuite = 64
	csp = &Parameters{Group: invalidGroup}
	if _, err := patchCipherSuite(csp); err == nil {
		t.Error("expected error on invalid group")
	}

	var invalidHash hash.Identifier = 64
	csp = &Parameters{Hash: invalidHash}
	if _, err := patchCipherSuite(csp); err == nil {
		t.Error("expected error on invalid hash function")
	}

	var invalidIHF ihf.Identifier = 64
	csp = &Parameters{IHF: invalidIHF}
	if _, err := patchCipherSuite(csp); err == nil {
		t.Error("expected error on invalid IHF")
	}
}

func TestNew(t *testing.T) {
	// Should error on nil or empty dst
	if _, err := New(nil, nil); err == nil {
		t.Error("expected error on nil dst")
	}

	if _, err := New(nil, []byte("")); err == nil {
		t.Error("expected error on empty dst")
	}

	// Should error on invalid group identifier
	invalidCSP := &Parameters{Group: 64}
	if _, err := New(invalidCSP, shortDST); err == nil {
		t.Error("expected error on invalid Encoding")
	}

	// Should succeed
	if _, err := New(nil, shortDST); err != nil {
		t.Errorf("unexpected error on valid input : %q", err)
	}
}

var (
	defCipherSuite, _ = New(nil, normalDST)
	defEncoding       = [4]byte{1, 4, 1, 64}
)

const defString = "ristretto255_XMD:SHA-512_R255MAP_RO_-SHA3-512-Argon2id-64"

func TestEncode(t *testing.T) {
	p := defCipherSuite.Parameters
	e := p.Encode()

	assert.Equal(t, defEncoding, e)
}

func TestReadCiphersuite(t *testing.T) {
	params, err := ReadCiphersuite(defEncoding)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, defCipherSuite.Parameters, params)

	// Should fail
	invalid := [4]byte{0, 0, 0, 0}

	params, err = ReadCiphersuite(invalid)
	if err == nil {
		t.Fatal("expected error on invalid encoding")
	}
}

func TestParameters_String(t *testing.T) {
	s := defCipherSuite.Parameters.String()
	assert.Equal(t, defString, s)
}
