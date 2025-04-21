package portalwire

import (
	"bytes"
	"testing"
)

func TestEncodeDecodeSingleContent(t *testing.T) {
	tests := []struct {
		name    string
		content []byte
	}{
		{"EmptyContent", []byte{}},
		{"ShortContent", []byte("hello")},
		{"BinaryContent", []byte{0x01, 0x02, 0x03, 0xFF}},
		{"LargeContent", bytes.Repeat([]byte{0xAA}, 1024)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded := encodeSingleContent(tt.content)
			decoded, remaining, err := decodeSingleContent(encoded)
			if err != nil {
				t.Fatalf("decodeSingleContent failed: %v", err)
			}
			if !bytes.Equal(decoded, tt.content) {
				t.Errorf("decoded content mismatch. got %v, want %v", decoded, tt.content)
			}
			if len(remaining) != 0 {
				t.Errorf("expected no remaining bytes, got %v", remaining)
			}
		})
	}
}

func TestDecodeSingleContent_InvalidData(t *testing.T) {
	data := encodeSingleContent([]byte("incomplete"))
	if len(data) < 2 {
		t.Fatalf("encoded data too short for this test")
	}
	corrupted := data[:len(data)-2]

	_, _, err := decodeSingleContent(corrupted)
	if err == nil {
		t.Error("expected error for insufficient data, got nil")
	}
}
