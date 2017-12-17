package lib

import (
	"io"
)

// Converts all occurrences of /r/n and /r to /n
type Normaliser struct {
	r        io.Reader
	lastChar byte
}

func NewNormaliser(r io.Reader) *Normaliser {
	return &Normaliser{r: r}
}

func (norm *Normaliser) Read(p []byte) (n int, err error) {
	n, err = norm.r.Read(p)
	for i := 0; i < n; i++ {
		switch {
		case p[i] == '\n' && norm.lastChar == '\r':
			copy(p[i:n], p[i+1:])
			norm.lastChar = p[i]
			n--
			i--
		case p[i] == '\r':
			norm.lastChar = p[i]
			p[i] = '\n'
		default:
			norm.lastChar = p[i]
		}
	}
	return
}
