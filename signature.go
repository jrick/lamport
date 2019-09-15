// Package lamport implements the Lamport signature scheme using the Blake2b-256
// hash function.
//
// Lamport keys are one time use.  A secret key must not sign more than one
// message.
package lamport

import (
	"bytes"
	"crypto/subtle"
	"io"

	"decred.org/cspp/chacha20prng"
	"golang.org/x/crypto/blake2b"
)

// SecretKey is a Lamport signature secret key seed.  Using a ChaCha20 PRNG, it
// is expanded to create 256 pairs of secret values (512 32-byte secrets in
// total) which together comprise the private key.
type SecretKey [32]byte

// PublicKey contains Blake2b-256 hashes of each of the 512 32-byte values of
// the expanded secret key.
type PublicKey [512 * 32]byte

// Signature is 256 32-byte values, from the 512 expanded secret key values,
// picked based on whether each of the 256 message hash bits were a 0 or 1.
//
// Because Signature is comprised of half of the values of the expanded secret
// key, and message verification reveals the pair positions of these secrets in
// the secret key, signing can only safely be performed once per message per
// secret key.
type Signature [256 * 32]byte

// GenerateKey derives a public and secret key, reading cryptographically-secure
// randomness from rand.
func GenerateKey(rand io.Reader) (pk *PublicKey, sk *SecretKey, err error) {
	sk = new(SecretKey)
	_, err = rand.Read(sk[:])
	if err != nil {
		return
	}

	y := new([512 * 32]byte)
	rng := chacha20prng.New(sk[:], 0)
	rng.Read(y[:]) // never errors

	pk = new(PublicKey)
	for i := 0; i < 512; i++ {
		h := blake2b.Sum256(y[i*32 : i*32+32])
		copy(pk[i*32:i*32+32], h[:])
	}

	return
}

// Sign signs message with sk.
func Sign(sk *SecretKey, message []byte) *Signature {
	messageHash := blake2b.Sum256(message)
	return SignHash(sk, messageHash[:])
}

// SignHash signs a 32-byte message hash.
// It will panic if the message hash is not exactly 32 bytes.
func SignHash(sk *SecretKey, messageHash []byte) *Signature {
	if len(messageHash) != 32 {
		panic("messageHash not 32 bytes")
	}

	y := new([512 * 32]byte)
	rng := chacha20prng.New(sk[:], 0)
	rng.Read(y[:]) // never errors

	sig := new(Signature)
	for i := 0; i < 256; i++ {
		mbyte := messageHash[i>>3]     // byte of current bit
		bit := mbyte >> (i & 0x07) & 1 // bit=0 or 1

		// copy first secret (when bit=0) or second (when bit=1) into bit's signature position
		bitsig := sig[i*32 : i*32+32]
		first := y[i*64 : i*64+32]
		second := y[i*64+32 : i*64+64]
		bits := byte(subtle.ConstantTimeSelect(int(bit), 0xFF, 0))
		for j := range bitsig {
			bitsig[j] = (^bits & first[j]) | (bits & second[j])
		}
	}

	return sig
}

// Verify checks whether sig is a valid signature created by the secret key of
// pk for message.
func Verify(pk *PublicKey, message []byte, sig *Signature) bool {
	messageHash := blake2b.Sum256(message)
	return VerifyHash(pk, messageHash[:], sig)
}

// VerifyHash checks whether sig is a valid signature created by the secret key
// of pk for a 32-byte message hash.
// It will panics if the message hash is not exactly 32 bytes.
func VerifyHash(pk *PublicKey, messageHash []byte, sig *Signature) bool {
	if len(messageHash) != 32 {
		panic("messageHash not 32 bytes")
	}

	// Pick expected hashes from the public key based on each bit of the message hash.
	expectedHashes := make([]byte, 0, 256*32)
	for i := 0; i < 256; i++ {
		mbyte := messageHash[i>>3]     // byte of current bit
		bit := mbyte >> (i & 0x07) & 1 // bit=0 or 1

		var expectedHash []byte
		if bit&1 == 0 {
			expectedHash = pk[i*64 : i*64+32]
		} else {
			expectedHash = pk[i*64+32 : i*64+64]
		}
		expectedHashes = append(expectedHashes, expectedHash...)
	}

	// Hash each secret from the signature
	sigHashes := make([]byte, 0, 256*32)
	for i := 0; i < 256; i++ {
		h := blake2b.Sum256(sig[i*32 : i*32+32])
		sigHashes = append(sigHashes, h[:]...)
	}

	// Signature is verified if all expected hashes equal each hash the signature's secrets.
	return bytes.Equal(sigHashes, expectedHashes)
}
