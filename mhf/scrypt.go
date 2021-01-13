package mhf

import (
	"fmt"

	"golang.org/x/crypto/scrypt"
)

const scrypts = "Scrypt"

var (
	defaultScryptTime    = 32768
	defaultScryptMemory  = 8
	defaultScryptThreads = 1
)

func defaultScrypt(password, salt []byte, length int) []byte {
	return scryptf(password, salt, defaultScryptTime, defaultScryptMemory, defaultScryptThreads, length)
}

func scryptf(password, salt []byte, time, memory, threads, length int) []byte {
	k, err := scrypt.Key(password, salt, time, memory, threads, length)
	if err != nil {
		panic(fmt.Errorf("unexpected error : %w", err))
	}

	return k
}

func scryptParams() *Parameters {
	return &Parameters{
		ID:        Scrypt,
		Time:      defaultScryptTime,
		Memory:    defaultScryptMemory,
		Threads:   defaultScryptThreads,
		KeyLength: DefaultLength,
	}
}
