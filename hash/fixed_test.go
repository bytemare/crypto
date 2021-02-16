package hash

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLongHmacKey(t *testing.T) {
	longHMACKey := []byte("Length65aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")

	for _, id := range []Hashing{SHA256, SHA512, SHA3_256, SHA3_512} {
		h := id.Get()

		assert.PanicsWithError(t, errHmacKeySize.Error(), func() {
			_ = h.Hmac(testData.message, longHMACKey)
		})
	}
}

func TestHmac(t *testing.T) {
	for _, id := range []Hashing{SHA256, SHA512, SHA3_256, SHA3_512} {
		h := id.Get()

		key, _ := hex.DecodeString(testData.key[h.OutputSize()])
		hmac := h.Hmac(testData.message, key)

		if len(hmac) != h.OutputSize() {
			t.Errorf("#%v : invalid hmac length", id)
		}
	}
}

func TestHKDF(t *testing.T) {
	for _, id := range []Hashing{SHA256, SHA512, SHA3_256, SHA3_512} {
		h := id.Get()

		for _, l := range []int{0, h.OutputSize()} {
			key := h.HKDF(testData.secret, testData.salt, testData.info, l)

			if len(key) != h.OutputSize() {
				t.Errorf("#%v : invalid key length (length argument = %d)", id, l)
			}
		}
	}
}

func TestHKDFExtract(t *testing.T) {
	for _, id := range []Hashing{SHA256, SHA512, SHA3_256, SHA3_512} {
		h := id.Get()

		for _, l := range []int{0, h.OutputSize()} {
			// Build a pseudorandom key
			prk := h.HKDFExtract(testData.secret, testData.salt)

			if len(prk) != h.OutputSize() {
				t.Errorf("#%v : invalid key length (length argument = %d)", id, l)
			}
		}
	}
}

func TestHKDFExpand(t *testing.T) {
	for _, id := range []Hashing{SHA256, SHA512, SHA3_256, SHA3_512} {
		h := id.Get()

		for _, l := range []int{0, h.OutputSize()} {
			// Build a pseudorandom key
			prk := h.HKDF(testData.secret, testData.salt, testData.info, l)
			key := h.HKDFExpand(prk, testData.info, l)

			if len(key) != h.OutputSize() {
				t.Errorf("#%v : invalid key length (length argument = %d)", id, l)
			}
		}
	}
}
