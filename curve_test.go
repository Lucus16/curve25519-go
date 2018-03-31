package curve25519

import "testing"
import "bytes"
import "fmt"

func ExampleECKeyPair() {
	keyPair, _ := GenerateKeyPair()
	fmt.Println(keyPair)
}

func TestGenerateKeyPair(t *testing.T) {
	keyPair, err := GenerateKeyPair()
	if err != nil {
		t.Error(err)
	}
	if len(keyPair.PrivateKey) != djbKeyLen {
		t.Fail()
	}
	if len(keyPair.PublicKey) != djbKeyLen {
		t.Fail()
	}
}

func TestCalculateAgreement(t *testing.T) {
	alice, err := GenerateKeyPair()
	if err != nil {
		t.Error(err)
	}
	bob, err := GenerateKeyPair()
	if err != nil {
		t.Error(err)
	}
	keyA, err := CalculateAgreement(bob.PublicKey, alice.PrivateKey)
	if err != nil {
		t.Error(err)
	}
	if len(keyA) != djbKeyLen {
		t.Fail()
	}
	keyB, err := CalculateAgreement(alice.PublicKey, bob.PrivateKey)
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(keyA, keyB) {
		t.Errorf("Calculated agreements differ")
	}
}

func TestSignature(t *testing.T) {
	keys, err := GenerateKeyPair()
	if err != nil {
		t.Error(err)
	}
	message := []byte("Hello world!")
	signature, err := CalculateSignature(keys.PrivateKey, message)
	if err != nil {
		t.Error(err)
	}
	good, err := VerifySignature(keys.PublicKey, message, signature)
	if err != nil {
		t.Error(err)
	}
	if !good {
		t.Errorf("Bad signature")
	}
}

func TestVrfSignature(t *testing.T) {
	keys, err := GenerateKeyPair()
	if err != nil {
		t.Error(err)
	}
	message := []byte("Hello world!")
	signature, err := CalculateVrfSignature(keys.PrivateKey, message)
	if err != nil {
		t.Error(err)
	}
	vrfOutput, err := VerifyVrfSignature(keys.PublicKey, message, signature)
	if err != nil {
		t.Error(err)
	}
	// TODO: Can any property of vrfOutput be checked?
	_ = vrfOutput
}
