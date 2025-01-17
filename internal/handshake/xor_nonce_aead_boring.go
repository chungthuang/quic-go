//go:build boringcrypto

package handshake

import (
	"crypto/boring"
	"crypto/cipher"
	"crypto/tls"
	"errors"
	"os"
)

var (
	useBoring             = len(os.Getenv("USE_BORING")) != 0
	errBoringIsNotEnabled = errors.New("boring was requested but not enabled")
	zeroNonce             = [aeadNonceLength]byte{}
)

func newAEAD(aes cipher.Block) (cipher.AEAD, error) {
	if useBoring {
		if boring.Enabled() {
			return tls.NewGCMTLS13(aes)
		} else {
			return nil, errBoringIsNotEnabled
		}
	} else {
		return cipher.NewGCM(aes)
	}
}

func allZeros(nonce []byte) bool {
	for _, e := range nonce {
		if e != 0 {
			return false
		}
	}
	return true
}

func (f *xorNonceAEAD) sealZeroNonce() {
	f.doSeal([]byte{}, zeroNonce[:], []byte{}, []byte{})
}

func (f *xorNonceAEAD) seal(out, nonce, plaintext, additionalData []byte) []byte {
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

	return f.doSeal(out, nonce, plaintext, additionalData)
}
