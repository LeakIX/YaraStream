package decoder

import (
	"bufio"
	"errors"
)

// Decoder is an interface for decoding archive containers
type Decoder interface {
	// Next will advance the container to the next entry and return its metadata
	Next() (*Entry, error)
	// Read is an io.Reader implementation on the current entry
	Read(p []byte) (int, error)
}

type Getter func(filename string, reader *bufio.Reader) (Decoder, error)

var ErrNotSupported = errors.New("not supported")

// GetDecoder will return the proper container decoder for a given reader
func GetDecoder(filename string, reader *bufio.Reader) (Decoder, error) {
	headerBytes, err := reader.Peek(4)
	if err != nil {
		return nil, err
	}
	for _, registration := range Registrations {
		if registration.MatchFileHeader(filename, headerBytes) {
			return registration.GetDecoder(filename, reader)
		}
	}
	return nil, ErrNotSupported
}

var Registrations []Registration

type Registration struct {
	MatchFileHeader func(string, []byte) bool
	GetDecoder      Getter
}

type Entry struct {
	Type     string
	Filename string
}

func (e Entry) IsFile() bool {
	return e.Type == "file"
}
func (e Entry) IsDir() bool {
	return e.Type == "dir"
}
