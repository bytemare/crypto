package utils

import (
	"bytes"
	"testing"
)

func TestRandomBytes(t *testing.T) {
	length := 32
	r := RandomBytes(length)

	if len(r) != length {
		t.Errorf("invalid random output length. Expected %d, got %d", length, len(r))
	}
}

func TestConcatenate(t *testing.T) {
	a := []byte("a")
	b := []byte("b")
	expected := []byte("ab")

	c := Concatenate(0, a, b)

	if !bytes.Equal(c, expected) {
		t.Errorf("failed to concatenate. Expected %v, got %v", expected, c)
	}

	if Concatenate(0, nil) != nil {
		t.Error("expected nil output for nil input")
	}
}
