package crypto

// Based on
// https://csrc.nist.gov/csrc/media/publications/fips/180/2/archive/2002-08-01/documents/fips180-2.pdf

import (
	"encoding/binary"
	"fmt"
)

func sha256_padMessage(str string) []uint8 {
	paddedLen := sha256_paddedLength(len(str))
	msg := make([]uint8, paddedLen)
	
	for i := 0; i < len(str); i++ {
		msg[i] = str[i]
	}
	msg[len(str)] = 0b10000000

	var msgLen uint64 = uint64(len(str)) * 8

	var bytes = make([]uint8, 8)
	binary.BigEndian.PutUint64(bytes, msgLen)

	for i := 0; i < len(bytes); i++ {
		msg[len(msg) - 8 + i] = bytes[i]
	}
	return msg
}
func sha256_createMessageSchedule(paddedMsg []byte, block int) [64]uint32 {
	W := [64]uint32{}
	for k := 0; k < 16; k++ {
		W[k] = binary.BigEndian.Uint32(paddedMsg[block * 64 + k * 4:block * 64 + 4 + k * 4])
	}
	for k := 16; k < 64; k++ {
		W[k] = sha256_ssigma1(W[k - 2]) + W[k - 7] + sha256_ssigma0(W[k - 15]) + W[k - 16]
	}
	return W
}

func sha256_computeRounds(H [8]uint32, W [64]uint32) [8]uint32  {
	// sha 256 magic values
	K := [64]uint32{
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
		0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
		0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
		0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
		0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
		0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
	}
	
	// Copy state
	a, b, c, d, e, f, g, h := H[0], H[1], H[2], H[3], H[4], H[5], H[6], H[7]

	// Compute rounds
	for i := 0; i < 64; i++ {
		t1 := h + sha256_sigma1(e) + sha256_ch(e, f, g) + K[i] + W[i]
		t2 := sha256_sigma0(a) + sha256_maj(a, b, c)
		h = g
		g = f
		f = e
		e = d + t1
		d = c
		c = b
		b = a
		a = t1 + t2
	}

	// Update state
	H[0] += a
	H[1] += b
	H[2] += c
	H[3] += d
	H[4] += e
	H[5] += f
	H[6] += g
	H[7] += h

	return H
}

func Sha256(str string) string {
	// Initial hash state
	H := [8]uint32{
		0x6a09e667, 
		0xbb67ae85, 
		0x3c6ef372, 
		0xa54ff53a,
		0x510e527f, 
		0x9b05688c, 
		0x1f83d9ab, 
		0x5be0cd19,
	}
	
	msg := sha256_padMessage(str)
	nBlocks := len(msg) / 64

	for block := 0; block < nBlocks; block++ {
		W := sha256_createMessageSchedule(msg, block)
		H = sha256_computeRounds(H, W)
	}

	return fmt.Sprintf("%08x%08x%08x%08x%08x%08x%08x%08x", H[0], H[1], H[2], H[3], H[4], H[5], H[6], H[7])
}
