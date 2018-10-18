package curve

import "testing"
import "bytes"

func TestGenerateKeypair(t *testing.T) {
	priv, pub, err := GenerateKeypair()
	if err != nil {
		t.Error(err)
	}

	if len(priv) != djbKeyLen {
		t.Errorf("Wrong private key length")
	}

	if len(pub) != djbKeyLen {
		t.Errorf("Wrong public key length")
	}
}

func TestCalculateAgreement(t *testing.T) {
	alicePriv, alicePub, err := GenerateKeypair()
	if err != nil {
		t.Error(err)
	}

	bobPriv, bobPub, err := GenerateKeypair()
	if err != nil {
		t.Error(err)
	}

	keyA, err := alicePriv.CalculateAgreement(bobPub)
	if err != nil {
		t.Error(err)
	}

	if len(keyA) != djbKeyLen {
		t.Errorf("Wrong agreement length")
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
	priv, pub, err := GenerateKeypair()
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
	priv, pub, err := GenerateKeypair()
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

func BenchmarkGenerateKeypair(b *testing.B) {
	for n := 0; n < b.N; n++ {
		GenerateKeypair()
	}
}
