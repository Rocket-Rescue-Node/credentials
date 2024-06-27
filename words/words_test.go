package words

import (
	"bytes"
	"testing"
)

func TestEncode(t *testing.T) {
	testCases := []struct {
		name     string
		input    []byte
		expected []string
	}{
		{
			name:     "Empty input",
			input:    []byte{},
			expected: []string{},
		},
		{
			name:     "Single byte",
			input:    []byte{0},
			expected: []string{"aardvark"},
		},
		{
			name:     "Two bytes",
			input:    []byte{0, 1},
			expected: []string{"aardvark", "adviser"},
		},
		{
			name:     "Alternating words",
			input:    []byte{0, 1, 2, 3},
			expected: []string{"aardvark", "adviser", "accrue", "alkali"},
		},
		{
			name:     "Wrap around word list",
			input:    []byte{255, 255},
			expected: []string{"zulu", "yucatan"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := Encode(tc.input)
			if len(result) != len(tc.expected) {
				t.Fatalf("Expected %d words, got %d", len(tc.expected), len(result))
			}
			for i, word := range result {
				if word != tc.expected[i] {
					t.Errorf("Word at index %d: expected '%s', got '%s'", i, tc.expected[i], word)
				}
			}
		})
	}
}

func TestWordsListCompleteness(t *testing.T) {
	if len(words) != 2 {
		t.Fatalf("Expected 2 word lists, got %d", len(words))
	}

	for i, list := range words {
		if len(list) != 256 {
			t.Errorf("Word list %d: expected 256 words, got %d", i, len(list))
		}

		// Check for duplicate words
		wordSet := make(map[string]bool)
		for _, word := range list {
			if wordSet[word] {
				t.Errorf("Word list %d: duplicate word found: %s", i, word)
			}
			wordSet[word] = true
		}
	}
}

func TestEncodeReversibility(t *testing.T) {
	// Test that we can reverse the encoding process
	input := make([]byte, 256)
	for i := range input {
		input[i] = byte(i)
	}

	encoded := Encode(input)
	decoded := make([]byte, len(input))

	for i, word := range encoded {
		for b, w := range words[i%2] {
			if w == word {
				decoded[i] = byte(b)
				break
			}
		}
	}

	if !bytes.Equal(input, decoded) {
		t.Error("Encode is not reversible")
	}
}
