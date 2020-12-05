package hash

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

type data struct {
	message []byte
	secret  []byte
	key     map[int]string
	salt    []byte
	info    []byte
}

var testData = &data{
	message: []byte("This is the message."),
	secret:  []byte("secret"),
	key: map[int]string{
		32: "2bb80d537b1da3e38bd30361aa855686bde0eacd7162fef6a25fe97bf527a25b",
		64: "bd2b1aaf7ef4f09be9f52ce2d8d599674d81aa9d6a4421696dc4d93dd0619d682ce56b4d64a9ef097761ced99e0f67265b5f76085e5b0ee7ca4696b2ad6fe2b2",
	},
	salt: nil,
	info: []byte("contextInfo"),
}

func TestAvailability(t *testing.T) {
	for id := range registered {
		if !id.Available() {
			t.Errorf("%v is not available, but should be", id)
		}
	}

	wrong := maxID
	if wrong.Available() {
		t.Errorf("%v is considered available when it should not", wrong)
	}
}

func TestLongHmacKey(t *testing.T) {
	longHMACKey := []byte("Length65aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")

	for _, params := range registered {
		h := params.id.Get()

		if h.Extensible() {
			assert.PanicsWithError(t, errForbiddenXOF.Error(), func() { _ = h.Hmac(nil, nil) })
			continue
		}

		assert.PanicsWithError(t, errHmacKeySize.Error(), func() {
			_ = h.Hmac(testData.message, longHMACKey)
		})
	}
}

func TestHash(t *testing.T) {
	for _, params := range registered {
		h := params.id.Get()

		hh := h.Hash(h.OutputSize(), testData.message)

		if len(hh) != h.OutputSize() {
			t.Errorf("#%v : invalid hash output length length. Expected %d, got %d", h.id, h.OutputSize(), len(hh))
		}
	}
}

func TestHmac(t *testing.T) {
	for _, params := range registered {
		h := params.id.Get()

		if h.Extensible() {
			assert.PanicsWithError(t, errForbiddenXOF.Error(), func() { _ = h.Hmac(nil, nil) })
			continue
		}

		key, _ := hex.DecodeString(testData.key[h.OutputSize()])
		hmac := h.Hmac(testData.message, key)

		if len(hmac) != h.OutputSize() {
			t.Errorf("#%v : invalid hmac length", h.id)
		}
	}
}

func TestHKDF(t *testing.T) {
	for _, params := range registered {
		h := params.id.Get()

		if h.Extensible() {
			assert.PanicsWithError(t, errForbiddenXOF.Error(), func() { _ = h.HKDF(nil, nil, nil, 0) })
			continue
		}

		for _, l := range []int{0, h.OutputSize()} {
			key := h.HKDF(testData.secret, testData.salt, testData.info, l)

			if len(key) != h.OutputSize() {
				t.Errorf("#%v : invalid key length (length argument = %d)", h.id, l)
			}
		}
	}
}

func TestDeriveKey(t *testing.T) {
	for _, params := range registered {
		h := params.id.Get()

		if h.Extensible() {
			assert.PanicsWithError(t, errForbiddenXOF.Error(), func() { _ = h.DeriveKey(nil, nil, 0) })
			continue
		}

		for _, l := range []int{0, h.OutputSize()} {
			// Build a pseudorandom key
			prk := h.HKDF(testData.secret, testData.salt, testData.info, l)
			key := h.DeriveKey(prk, testData.info, l)

			if len(key) != h.OutputSize() {
				t.Errorf("#%v : invalid key length (length argument = %d)", h.id, l)
			}
		}
	}
}

func TestSmallXOFOutput(t *testing.T) {
	for _, params := range registered {
		h := params.id.Get()

		if !h.Extensible() {
			continue
		}

		assert.Panics(t, func() {
			_ = h.Hash(h.OutputSize()-1, testData.message)
		})

	}
}
