package credentials

import (
	"bytes"
	"strings"
)

type ID struct {
	words []string
	bytes [32]byte
}

func (i *ID) StringWithLength(length uint8) string {
	if length > 32 || length == 0 {
		length = 32
	}

	words := i.words[:length]
	return strings.Join(words, "-")
}

func (i *ID) String() string {
	return i.StringWithLength(4)
}

func (i *ID) Equals(b *ID) bool {
	return bytes.Equal(i.bytes[:], b.bytes[:])
}
