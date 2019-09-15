package lamport

import (
	"bytes"
	"testing"

	"decred.org/cspp/chacha20prng"
	"golang.org/x/crypto/blake2b"
)

var (
	message     = []byte("message")
	messageHash = blake2b.Sum256(message)
	seed        = make([]byte, 32)
	rng         = chacha20prng.New(seed, 0)
	pk, sk, _   = GenerateKey(rng)
	sig         = SignHash(sk, messageHash[:])
)

// TestSignatureConstruction recreates a signature in an obvious but not
// constant-time manner and verifies equality with the constant-time
// implementation.
func TestSignatureConstruction(t *testing.T) {
	y := new([512 * 32]byte)
	chacha20prng.New(sk[:], 0).Read(y[:])
	expected := make([]byte, 0, 256*32)
	for i := 0; i < 32; i++ {
		mbyte := messageHash[i]
		for j := 0; j < 8; j++ {
			bitIsOne := (mbyte>>j)&1 == 1
			t.Logf("i=%d j=%d mbyte=%08b %v", i, j, mbyte, bitIsOne)
			if !bitIsOne {
				expected = append(expected, y[(i*8+j)*64:(i*8+j)*64+32]...)
			} else {
				expected = append(expected, y[(i*8+j)*64+32:(i*8+j)*64+64]...)
			}
		}
	}

	if !bytes.Equal(sig[:], expected) {
		t.Logf("sig secrets\texpected secrets\n")
		for i := 0; i < 256; i++ {
			t.Logf("%x\t%x\n", sig[i*32:i*32+32], expected[i*32:i*32+32])
		}
		t.Fatal("signature doesn't match expected")
	}
}

func TestVerify(t *testing.T) {
	if !VerifyHash(pk, messageHash[:], sig) {
		t.Fatal("correct signature fails verify")
	}
}

func BenchmarkSignVerifyHash(b *testing.B) {
	for i := 0; i < b.N; i++ {
		sig := SignHash(sk, messageHash[:])
		if !VerifyHash(pk, messageHash[:], sig) {
			b.Fatal("verify")
		}
	}
}
