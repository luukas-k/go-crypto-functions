package crypto

// Based on
// https://csrc.nist.gov/csrc/media/publications/fips/180/2/archive/2002-08-01/documents/fips180-2.pdf

import (
	"encoding/binary"
	"fmt"
)

func sha512_padMessage(str string) []uint8 {
	paddedLen := sha512_paddedLength(len(str))
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

func sha512_createMessageSchedule(paddedMsg []byte, block int) [80]uint64 {
	W := [80]uint64{}
	for k := 0; k < 16; k++ {
		W[k] = binary.BigEndian.Uint64(paddedMsg[block * 128 + k * 8:block * 128 + 8 + k * 8])
	}
	for k := 16; k < 80; k++ {
		W[k] = sha512_ssigma1(W[k - 2]) + W[k - 7] + sha512_ssigma0(W[k - 15]) + W[k - 16]
	}
	return W
}

func sha512_computeRounds(H [8]uint64, W [80]uint64) [8]uint64  {
	// sha 512 magic values
	K := [80]uint64{
		0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
		0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
		0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
		0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
		0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
		0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
		0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
		0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
		0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
		0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
		0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
		0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
		0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
		0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
		0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
		0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
		0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
		0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
		0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
		0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,		
	}
	
	// Copy state
	a, b, c, d, e, f, g, h := H[0], H[1], H[2], H[3], H[4], H[5], H[6], H[7]

	// Compute rounds
	for i := 0; i < 80; i++ {
		t1 := h + sha512_sigma1(e) + sha512_ch(e, f, g) + K[i] + W[i]
		t2 := sha512_sigma0(a) + sha512_maj(a, b, c)
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

func Sha512(str string) string {
	// Initial hash state
	H := [8]uint64{
		0x6a09e667f3bcc908,
		0xbb67ae8584caa73b,
		0x3c6ef372fe94f82b,
		0xa54ff53a5f1d36f1,
		0x510e527fade682d1,
		0x9b05688c2b3e6c1f,
		0x1f83d9abfb41bd6b,
		0x5be0cd19137e2179,
	}

	msg := sha512_padMessage(str)
	nBlocks := len(msg) / 128

	for block := 0; block < nBlocks; block++ {
		W := sha512_createMessageSchedule(msg, block)
		H = sha512_computeRounds(H, W)
	}

	return fmt.Sprintf("%016x%016x%016x%016x%016x%016x%016x%016x", H[0], H[1], H[2], H[3], H[4], H[5], H[6], H[7])
}
