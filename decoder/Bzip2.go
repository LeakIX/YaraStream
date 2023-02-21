package decoder

import (
	"bytes"
	"compress/bzip2"
	"io"
	"strings"
)

func init() {
	Registrations = append(Registrations, Registration{
		MatchFileHeader: func(_ string, headerBytes []byte) bool {
			return bytes.HasPrefix(headerBytes, []byte("BZh"))
		},
		GetDecoder: GetBzip2Decoder,
	})
}

type Bzip2Decoder struct {
	reader   io.Reader
	done     bool
	filename string
}

func GetBzip2Decoder(filename string, reader io.Reader) (Decoder, error) {
	bzReader := bzip2.NewReader(reader)
	return &Bzip2Decoder{
		done:     false,
		reader:   bzReader,
		filename: filename,
	}, nil
}

func (d *Bzip2Decoder) Read(p []byte) (int, error) {
	return d.reader.Read(p)
}

func (d *Bzip2Decoder) Next() (*Entry, error) {
	if d.done {
		return nil, io.EOF
	}
	d.done = true
	return &Entry{
		Filename: strings.TrimSuffix(d.filename, ".bz2"),
		Type:     "file",
	}, nil
}
