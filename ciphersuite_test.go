package cryptotools

import (
	"testing"

	"github.com/bytemare/cryptotools/group/ciphersuite"

	"github.com/stretchr/testify/assert"

	"github.com/bytemare/cryptotools/hash"
	"github.com/bytemare/cryptotools/mhf"
)

var (
	shortDST  = []byte("shortDST")
	normalDST = []byte("CryptoTools-Test00")
)

func TestPatchCiphersuite(t *testing.T) {
	defaultCSP := &Parameters{
		Group:  defGroup,
		Hash:   defHash,
		MHF:    defMHF,
		MHFLen: defMHFLen,
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
	var invalidGroup ciphersuite.Identifier = 64
	csp = &Parameters{Group: invalidGroup}
	if _, err := patchCipherSuite(csp); err == nil {
		t.Error("expected error on invalid group")
	}

	var invalidHash hash.Identifier = 64
	csp = &Parameters{Hash: invalidHash}
	if _, err := patchCipherSuite(csp); err == nil {
		t.Error("expected error on invalid hash function")
	}

	var invalidMHF mhf.Identifier = 64
	csp = &Parameters{MHF: invalidMHF}
	if _, err := patchCipherSuite(csp); err == nil {
		t.Error("expected error on invalid MHF")
	}
}

func TestNew(t *testing.T) {
	// Should error on nil, empty, or short dst
	_, err := New(nil, nil)
	assert.EqualError(t, err, errShortDST.Error(), "expected error on nil dst")

	_, err = New(nil, []byte(""))
	assert.EqualError(t, err, errShortDST.Error(), "expected error on empty dst")

	_, err = New(nil, shortDST)
	assert.EqualError(t, err, errShortDST.Error(), "expected error on short dst")

	// Should error on invalid group identifier
	invalidCSP := &Parameters{Group: 64}
	_, err = New(invalidCSP, normalDST)
	assert.EqualError(t, err, errInvalidGroupID.Error(), "expected error on invalid Encoding")

	// Should error on invalid hash identifier
	invalidCSP = &Parameters{Hash: 64}
	_, err = New(invalidCSP, normalDST)
	assert.Error(t, errInvalidHashID, "expected error on invalid Encoding")

	// Should error on invalid MHF identifier
	invalidCSP = &Parameters{MHF: 64}
	_, err = New(invalidCSP, normalDST)
	assert.Error(t, errInvalidMHFID, "expected error on invalid Encoding")

	// Should succeed
	if _, err := New(nil, normalDST); err != nil {
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
