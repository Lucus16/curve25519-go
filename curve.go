// Package curve is a thin wrapper around the libsignal curve25519
// implementation. It aims to be the Go equivalent of
// https://github.com/signalapp/curve25519-java
package curve // import "github.com/Lucus16/curve25519-go"

import "crypto/rand"
import "fmt"

// #cgo CFLAGS: -g -Wall -Wextra -Wno-sign-compare -Wno-unused-parameter -O3
// #include <stdint.h>
// #include "curve25519-donna.h"
// #include "curve_sigs.h"
// #include "gen_x.h"
import "C"

const djbKeyLen = 0x20
const curveSignatureLen = 0x40
const vrfSignatureLen = 0x60
const vrfVerifyLen = 0x20

type u8p = *C.uchar

type PrivateKey []byte
type PublicKey []byte

type CError struct {
	Fn   string
	Code int
}

func (err CError) Error() string {
	return fmt.Sprintf("C function %s failed with code %d", err.Fn, err.Code)
}

func newCError(fn string, code C.int) error {
	if code >= 0 {
		return nil
	} else {
		return CError{fn, int(code)}
	}
}

func GeneratePrivateKey() (key PrivateKey, err error) {
	key = make([]byte, djbKeyLen)
	_, err = rand.Read(key)
	if err != nil {
		return
	}

	key[0] &= 0xf8
	key[0x1f] &= 0x7f
	key[0x1f] |= 0x40
	return
}

func (privateKey PrivateKey) GeneratePublicKey() (publicKey PublicKey, err error) {
	if len(privateKey) != djbKeyLen {
		return nil, fmt.Errorf("Bad key length: %d", len(privateKey))
	}

	publicKey = make([]byte, djbKeyLen)
	basepoint := [djbKeyLen]byte{9}
	result := C.curve25519_donna(u8p(&publicKey[0]),
		u8p(&privateKey[0]), u8p(&basepoint[0]))
	return publicKey, newCError("curve25519_donna", result)
}

func GenerateKeypair() (privKey PrivateKey, pubKey PublicKey, err error) {
	privKey, err = GeneratePrivateKey()
	if err != nil {
		return
	}

	pubKey, err = privKey.GeneratePublicKey()
	if err != nil {
		return
	}

	return
}

func (privateKey PrivateKey) CalculateAgreement(publicKey PublicKey) (sharedKey []byte, err error) {
	if len(publicKey) != djbKeyLen {
		return nil, fmt.Errorf("Bad key length: %d", len(publicKey))
	}

	if len(privateKey) != djbKeyLen {
		return nil, fmt.Errorf("Bad key length: %d", len(privateKey))
	}

	sharedKey = make([]byte, djbKeyLen)
	result := C.curve25519_donna(u8p(&sharedKey[0]),
		u8p(&privateKey[0]), u8p(&publicKey[0]))
	return sharedKey, newCError("curve25519_donna", result)
}

func (key PrivateKey) CalculateSignature(message []byte) (signature []byte, err error) {
	if len(key) != djbKeyLen {
		return nil, fmt.Errorf("Bad key length: %d", len(key))
	}

	var random_data [curveSignatureLen]byte
	_, err = rand.Read(random_data[:])
	if err != nil {
		return
	}

	signature = make([]byte, curveSignatureLen)
	result := C.curve25519_sign(u8p(&signature[0]), u8p(&key[0]),
		u8p(&message[0]), C.size_t(len(message)), u8p(&random_data[0]))
	return signature, newCError("curve25519_sign", result)
}

func (key PublicKey) VerifySignature(message []byte, signature []byte) (good bool, err error) {
	if len(key) != djbKeyLen {
		return false, fmt.Errorf("Bad key length: %d", len(key))
	}

	if len(signature) != curveSignatureLen {
		return false, fmt.Errorf("Bad signature length: %d", len(signature))
	}

	result := C.curve25519_verify(u8p(&signature[0]), u8p(&key[0]),
		u8p(&message[0]), C.size_t(len(message)))
	return result == 0, newCError("curve25519_verify", result)
}

func (key PrivateKey) CalculateVrfSignature(message []byte) (signature []byte, err error) {
	if len(key) != djbKeyLen {
		return nil, fmt.Errorf("Bad key length: %d", len(key))
	}

	var random_data [vrfSignatureLen]byte
	_, err = rand.Read(random_data[:])
	if err != nil {
		return
	}

	signature = make([]byte, vrfSignatureLen)
	result := C.generalized_xveddsa_25519_sign(u8p(&signature[0]),
		u8p(&key[0]), u8p(&message[0]), C.size_t(len(message)),
		u8p(&random_data[0]), nil, C.ulong(0))
	return signature, newCError("generalized_xveddsa_25519_sign", result)
}

func (key PublicKey) VerifyVrfSignature(message []byte, signature []byte) (vrfOutput []byte, err error) {
	if len(key) != djbKeyLen {
		return nil, fmt.Errorf("Bad key length: %d", len(key))
	}

	if len(signature) != vrfSignatureLen {
		return nil, fmt.Errorf("Bad signature length: %d", len(signature))
	}

	vrfOutput = make([]byte, vrfVerifyLen)
	result := C.generalized_xveddsa_25519_verify(u8p(&vrfOutput[0]),
		u8p(&signature[0]), u8p(&key[0]), u8p(&message[0]),
		C.size_t(len(message)), nil, C.ulong(0))
	return vrfOutput, newCError("generalized_xveddsa_25519_verify", result)
}
