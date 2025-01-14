package handshake

import (
	"crypto"
	"crypto/aes"
	"crypto/boring"
	"crypto/cipher"
	"crypto/tls"
	"errors"
	"fmt"
	"os"

	"golang.org/x/crypto/chacha20poly1305"
)

// These cipher suite implementations are copied from the standard library crypto/tls package.

const (
	aeadNonceLength = 12
)

var (
	useBoring             = len(os.Getenv("USE_BORING")) != 0
	errBoringIsNotEnabled = errors.New("boring was requested but not enabled")
	zeroNonce             = [aeadNonceLength]byte{}
)

type cipherSuite struct {
	ID     uint16
	Hash   crypto.Hash
	KeyLen int
	AEAD   func(key, nonceMask []byte) *xorNonceAEAD
}

func (s cipherSuite) IVLen() int { return aeadNonceLength }

func getCipherSuite(id uint16) *cipherSuite {
	switch id {
	case tls.TLS_AES_128_GCM_SHA256:
		return &cipherSuite{ID: tls.TLS_AES_128_GCM_SHA256, Hash: crypto.SHA256, KeyLen: 16, AEAD: aeadAESGCMTLS13}
	case tls.TLS_CHACHA20_POLY1305_SHA256:
		return &cipherSuite{ID: tls.TLS_CHACHA20_POLY1305_SHA256, Hash: crypto.SHA256, KeyLen: 32, AEAD: aeadChaCha20Poly1305}
	case tls.TLS_AES_256_GCM_SHA384:
		return &cipherSuite{ID: tls.TLS_AES_256_GCM_SHA384, Hash: crypto.SHA384, KeyLen: 32, AEAD: aeadAESGCMTLS13}
	default:
		panic(fmt.Sprintf("unknown cypher suite: %d", id))
	}
}

func aeadAESGCMTLS13(key, nonceMask []byte) *xorNonceAEAD {
	if len(nonceMask) != aeadNonceLength {
		panic("tls: internal error: wrong nonce length")
	}
	aes, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	var aead cipher.AEAD
	if useBoring {
		if boring.Enabled() {
			aead, err = tls.NewGCMTLS13(aes)
		} else {
			err = errBoringIsNotEnabled
		}
	} else {
		aead, err = cipher.NewGCM(aes)
	}
	if err != nil {
		panic(err)
	}

	ret := &xorNonceAEAD{aead: aead, hasSeenNonceZero: false}
	copy(ret.nonceMask[:], nonceMask)
	return ret
}

func aeadChaCha20Poly1305(key, nonceMask []byte) *xorNonceAEAD {
	if len(nonceMask) != aeadNonceLength {
		panic("tls: internal error: wrong nonce length")
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		panic(err)
	}

	ret := &xorNonceAEAD{aead: aead}
	copy(ret.nonceMask[:], nonceMask)
	return ret
}

// xorNonceAEAD wraps an AEAD by XORing in a fixed pattern to the nonce
// before each call.
type xorNonceAEAD struct {
	nonceMask        [aeadNonceLength]byte
	aead             cipher.AEAD
	hasSeenNonceZero bool // This value denotes if the aead field was used with a nonce = 0
}

func (f *xorNonceAEAD) NonceSize() int        { return 8 } // 64-bit sequence number
func (f *xorNonceAEAD) Overhead() int         { return f.aead.Overhead() }
func (f *xorNonceAEAD) explicitNonceLen() int { return 0 }

func allZeros(nonce []byte) bool {
	for _, e := range nonce {
		if e != 0 {
			return false
		}
	}
	return true
}

func (f *xorNonceAEAD) Seal(out, nonce, plaintext, additionalData []byte) []byte {
	if useBoring {
		if boring.Enabled() {
			if !f.hasSeenNonceZero {
				// BoringSSL expects that the first nonce passed to the
				// AEAD instance is zero.
				// At this point the nonce argument is either zero or
				// an artificial one will be passed to the AEAD through
				// [sealZeroNonce]
				f.hasSeenNonceZero = true
				if !allZeros(nonce) {
					f.sealZeroNonce()
				}
			}
		} else {
			panic(errBoringIsNotEnabled)
		}
	}

	return f.seal(nonce, out, plaintext, additionalData)
}

func (f *xorNonceAEAD) sealZeroNonce() {
	zeroNonce := [aeadNonceLength]byte{}
	f.seal([]byte{}, zeroNonce[:], []byte{}, []byte{})
}

func (f *xorNonceAEAD) seal(nonce []byte, out []byte, plaintext []byte, additionalData []byte) []byte {
	for i, b := range nonce {
		f.nonceMask[4+i] ^= b
	}
	result := f.aead.Seal(out, f.nonceMask[:], plaintext, additionalData)
	for i, b := range nonce {
		f.nonceMask[4+i] ^= b
	}

	return result
}

func (f *xorNonceAEAD) Open(out, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	for i, b := range nonce {
		f.nonceMask[4+i] ^= b
	}
	result, err := f.aead.Open(out, f.nonceMask[:], ciphertext, additionalData)
	for i, b := range nonce {
		f.nonceMask[4+i] ^= b
	}

	return result, err
}
