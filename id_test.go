package credentials

import (
	"strings"
	"testing"
)

// TestIDString tests the String and StringWithLength functions of the ID type
func TestIDString(t *testing.T) {
	// Create a CredentialManager to get an ID
	cm := NewCredentialManager([]byte("ID string test secret"))
	id := cm.ID()

	// Test String() method (default 4-word representation)
	defaultStr := id.String()
	defaultWords := strings.Split(defaultStr, "-")
	if len(defaultWords) != 4 {
		t.Errorf("Expected 4 words in default String(), got %d", len(defaultWords))
	}

	// Test StringWithLength() with various lengths
	testCases := []struct {
		length   uint8
		expected int
	}{
		{0, 32}, // 0 should default to full length (32)
		{1, 1},
		{4, 4},
		{16, 16},
		{32, 32},
		{33, 32},  // >32 should be capped at 32
		{255, 32}, // large number should be capped at 32
	}

	for _, tc := range testCases {
		result := id.StringWithLength(tc.length)
		words := strings.Split(result, "-")
		if len(words) != tc.expected {
			t.Errorf("StringWithLength(%d) returned %d words, expected %d", tc.length, len(words), tc.expected)
		}
	}

	// Test consistency of StringWithLength
	fullStr := id.StringWithLength(32)
	for i := uint8(1); i <= 32; i++ {
		partialStr := id.StringWithLength(i)
		if !strings.HasPrefix(fullStr, partialStr) {
			t.Errorf("StringWithLength(%d) is not a prefix of the full string", i)
		}
	}

	// Test Equals method
	id2 := cm.ID() // Should be the same as id
	if !id.Equals(id2) {
		t.Error("ID.Equals() failed for identical IDs")
	}

	diffCm := NewCredentialManager([]byte("Different secret"))
	id3 := diffCm.ID()
	if id.Equals(id3) {
		t.Error("ID.Equals() unexpectedly returned true for different IDs")
	}
}
