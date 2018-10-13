package curve

import "testing"
import "bytes"
import "fmt"

func ExampleKeyPair() {
	priv, pub, _ := GenerateKeyPair()
	fmt.Println(priv)
	fmt.Println(pub)
}

func TestGenerateKeyPair(t *testing.T) {
	priv, pub, err := GenerateKeyPair()
	if err != nil {
		t.Error(err)
	}
	if len(priv) != djbKeyLen {
		t.Fail()
	}
	if len(pub) != djbKeyLen {
		t.Fail()
	}
}

func TestCalculateAgreement(t *testing.T) {
	alicePriv, alicePub, err := GenerateKeyPair()
	if err != nil {
		t.Error(err)
	}
	bobPriv, bobPub, err := GenerateKeyPair()
	if err != nil {
		t.Error(err)
	}
	keyA, err := alicePriv.CalculateAgreement(bobPub)
	if err != nil {
		t.Error(err)
	}
	if len(keyA) != djbKeyLen {
		t.Fail()
	}
	keyB, err := bobPriv.CalculateAgreement(alicePub)
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(keyA, keyB) {
		t.Errorf("Calculated agreements differ")
	}
}

func TestSignature(t *testing.T) {
	priv, pub, err := GenerateKeyPair()
	if err != nil {
		t.Error(err)
	}
	message := []byte("Hello world!")
	signature, err := priv.CalculateSignature(message)
	if err != nil {
		t.Error(err)
	}
	for i, _ := range signature {
		signature[i] ^= 1
		good, err := pub.VerifySignature(message, signature)
		if err == nil && good {
			t.Errorf("Expected bad signature")
		}
		signature[i] ^= 1
	}
	good, err := pub.VerifySignature(message, signature)
	if err != nil {
		t.Error(err)
	}
	if !good {
		t.Errorf("Bad signature")
	}
}

func TestVrfSignature(t *testing.T) {
	priv, pub, err := GenerateKeyPair()
	if err != nil {
		t.Error(err)
	}
	message := []byte("Hello world!")
	signature, err := priv.CalculateVrfSignature(message)
	if err != nil {
		t.Error(err)
	}
	vrfOutput, err := pub.VerifyVrfSignature(message, signature)
	if err != nil {
		t.Error(err)
	}
	// TODO: Can any property of vrfOutput be checked?
	_ = vrfOutput
}
