package crypto

import (
	"math/bits"
)

// SHA-256 functions

func sha256_paddedLength(dataLength int) int {
	padBytes := (((64 - (dataLength + 8 + 1)) % 64) + 64) % 64
	// L = n bytes of data, 1 byte for '1', padBytes for '0', 8 bytes of length
	return dataLength + 1 + padBytes + 8
}
func sha256_ssigma0(n uint32) uint32 {
	return bits.RotateLeft32(n, -7) ^ bits.RotateLeft32(n, -18) ^ (n >> 3)
}
func sha256_ssigma1(n uint32) uint32 {
	return bits.RotateLeft32(n, -17) ^ bits.RotateLeft32(n, -19) ^ (n >> 10)
}
func sha256_sigma0(n uint32) uint32 {
	return bits.RotateLeft32(n, -2) ^ bits.RotateLeft32(n, -13) ^ bits.RotateLeft32(n, -22)
}
func sha256_sigma1(n uint32) uint32 {
	return bits.RotateLeft32(n, -6) ^ bits.RotateLeft32(n, -11) ^ bits.RotateLeft32(n, -25)
}
func sha256_ch(a uint32, b uint32, c uint32) uint32 {
	return (a & b) ^ (^a & c)
}
func sha256_maj(a uint32, b uint32, c uint32) uint32 {
	return (a & b) ^ (a & c) ^ (b & c)
}

// SHA-512 functions

func sha512_paddedLength(dataLength int) int {
	padBytes := (((128 - (dataLength + 8 + 1)) % 128) + 128) % 128
	// L = n bytes of data, 1 byte for '1', padBytes for '0', 8 bytes of length
	return dataLength + 1 + padBytes + 8
}
func sha512_ssigma0(n uint64) uint64 {
	return bits.RotateLeft64(n, -1) ^ bits.RotateLeft64(n, -8) ^ (n >> 7)
}
func sha512_ssigma1(n uint64) uint64 {
	return bits.RotateLeft64(n, -19) ^ bits.RotateLeft64(n, -61) ^ (n >> 6)
}
func sha512_sigma0(n uint64) uint64 {
	return bits.RotateLeft64(n, -28) ^ bits.RotateLeft64(n, -34) ^ bits.RotateLeft64(n, -39)
}
func sha512_sigma1(n uint64) uint64 {
	return bits.RotateLeft64(n, -14) ^ bits.RotateLeft64(n, -18) ^ bits.RotateLeft64(n, -41)
}
func sha512_ch(a uint64, b uint64, c uint64) uint64 {
	return (a & b) ^ (^a & c)
}
func sha512_maj(a uint64, b uint64, c uint64) uint64 {
	return (a & b) ^ (a & c) ^ (b & c)
}
