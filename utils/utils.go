// Package utils provides some wrappers to commonly used functions.
package utils

import (
	"crypto/rand"
	"fmt"
)

const (
	bufLen = 100
)

// RandomBytes returns random bytes of length len (wrapper for crypto/rand).
func RandomBytes(length int) []byte {
	r := make([]byte, length)
	for {
		if _, err := rand.Read(r); err != nil {
			// We can as well not panic and try again through the loop
			panic(fmt.Errorf("unexpected error in generating random bytes : %w", err))
		}

		break
	}

	return r
}

// Concatenate takes the variadic array of input and returns a concatenation of it.
func Concatenate(length int, input ...[]byte) []byte {
	if len(input) == 0 {
		return nil
	}

	if len(input) == 1 {
		return input[0]
	}

	if length == 0 {
		length = bufLen
	}

	buf := make([]byte, 0, length)
	l := 0

	for _, in := range input {
		l += len(in)
		buf = append(buf, in...)
	}

	return buf
}
