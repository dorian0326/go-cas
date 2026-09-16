package main

import (
	"bytes"
	"testing"
)

func TestCopyEncryptDecrypt(t *testing.T) {
	payload := "Foo not bar"
	src := bytes.NewReader([]byte(payload))
	dst := new(bytes.Buffer)
	key := newEncryptionKey()

	n, err := copyEncrypt(key, src, dst)
	if err != nil {
		t.Fatal(err)
	}

	// nonce(12) + ciphertext(len(payload)) + tag(16)
	wantCipherLen := 12 + len(payload) + 16
	if n != wantCipherLen || dst.Len() != wantCipherLen {
		t.Fatalf("ciphertext length: got n=%d dst=%d, want %d", n,
			dst.Len(), wantCipherLen)
	}
	out := new(bytes.Buffer)
	nw, err := copyDecrypt(key, dst, out)
	if err != nil {
		t.Fatal(err)
	}
	if nw != len(payload) {
		t.Fatalf("plaintext length: got %d, want %d", nw, len(payload))
	}

	if out.String() != payload {
		t.Errorf("decryption failed: got %q, want %q", out.String(), payload)
	}
}

func TestCopyDecryptTampered(t *testing.T) {
	payload := []byte("Foo not bar")
	key := newEncryptionKey()
	dst := new(bytes.Buffer)

	if _, err := copyEncrypt(key, bytes.NewReader(payload), dst); err != nil {
		t.Fatal(err)
	}

	buf := dst.Bytes()
	buf[len(buf)-1] ^= 0x01

	out := new(bytes.Buffer)
	if _, err := copyDecrypt(key, bytes.NewReader(buf), out); err == nil {
		t.Fatal("expected authentication error, got nil")
	}
	if out.Len() != 0 {
		t.Fatalf("wrote %d bytes on failed decrypt", out.Len())
	}
}
