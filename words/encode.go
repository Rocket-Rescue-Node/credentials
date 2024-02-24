package words

// Encode converts a byte slice to a series of PGP wordlist words.
func Encode(key []byte) []string {
	out := make([]string, len(key))
	for i, b := range key {
		out[i] = words[i%2][b]
	}
	return out
}
