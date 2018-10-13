// Package curve is a thin wrapper around the libsignal curve25519
// implementation. It aims to be the Go equivalent of
// https://github.com/signalapp/curve25519-java
package curve

import "crypto/rand"
import "fmt"

// #cgo CFLAGS: -g -Ilibsignal-protocol-c/src/curve25519
// #cgo LDFLAGS: -Llibsignal-protocol-c/build/src -lsignal-protocol-c
// #include <stdint.h>
// #include "curve25519-donna.h"
// #include "ed25519/additions/curve_sigs.h"
// #include "ed25519/additions/generalized/gen_x.h"
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
	return fmt.Sprintf("C Function %v failed with code %v", err.Fn, err.Code)
}

func newCError(fn string, code C.int) error {
	if code >= 0 {
		return nil
	} else {
		return CError{fn, int(code)}
	}
}

func generatePrivateKey() (key PrivateKey, err error) {
	key = make([]byte, djbKeyLen)
	_, err = rand.Read(key)
	if err != nil {
		return
	}
	key[0] &= 248
	key[31] &= 127
	key[31] |= 64
	return
}

func generatePublicKey(privateKey PrivateKey) (publicKey PublicKey, err error) {
	if len(privateKey) != djbKeyLen {
		return nil, fmt.Errorf("Bad key length: %v", len(privateKey))
	}
	publicKey = make([]byte, djbKeyLen)
	basepoint := [djbKeyLen]byte{9}
	result := C.curve25519_donna(u8p(&publicKey[0]),
		u8p(&privateKey[0]), u8p(&basepoint[0]))
	return publicKey, newCError("curve25519_donna", result)
}

func GenerateKeyPair() (privKey PrivateKey, pubKey PublicKey, err error) {
	privKey, err = generatePrivateKey()
	if err != nil {
		return
	}
	pubKey, err = generatePublicKey(privKey)
	if err != nil {
		return
	}
	return
}

func (privateKey PrivateKey) CalculateAgreement(publicKey PublicKey) (sharedKey []byte, err error) {
	if len(publicKey) != djbKeyLen {
		return nil, fmt.Errorf("Bad key length: %v", len(publicKey))
	}
	if len(privateKey) != djbKeyLen {
		return nil, fmt.Errorf("Bad key length: %v", len(privateKey))
	}
	sharedKey = make([]byte, djbKeyLen)
	result := C.curve25519_donna(u8p(&sharedKey[0]),
		u8p(&privateKey[0]), u8p(&publicKey[0]))
	return sharedKey, newCError("curve25519_donna", result)
}

func (key PrivateKey) CalculateSignature(message []byte) (signature []byte, err error) {
	if len(key) != djbKeyLen {
		return nil, fmt.Errorf("Bad key length: %v", len(key))
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
		return false, fmt.Errorf("Bad key length: %v", len(key))
	}
	if len(signature) != curveSignatureLen {
		return false, fmt.Errorf("Bad signature length: %v", len(signature))
	}
	result := C.curve25519_verify(u8p(&signature[0]), u8p(&key[0]),
		u8p(&message[0]), C.size_t(len(message)))
	return result == 0, newCError("curve25519_verify", result)
}

func (key PrivateKey) CalculateVrfSignature(message []byte) (signature []byte, err error) {
	if len(key) != djbKeyLen {
		return nil, fmt.Errorf("Bad key length: %v", len(key))
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
		return nil, fmt.Errorf("Bad key length: %v", len(key))
	}
	if len(signature) != vrfSignatureLen {
		return nil, fmt.Errorf("Bad signature length: %v", len(signature))
	}
	vrfOutput = make([]byte, vrfVerifyLen)
	result := C.generalized_xveddsa_25519_verify(u8p(&vrfOutput[0]),
		u8p(&signature[0]), u8p(&key[0]), u8p(&message[0]),
		C.size_t(len(message)), nil, C.ulong(0))
	return vrfOutput, newCError("generalized_xveddsa_25519_verify", result)
}
