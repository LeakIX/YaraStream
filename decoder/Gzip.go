package decoder

import (
	"bytes"
	"compress/gzip"
	"io"
	"strings"
)

type GzDecoder struct {
	reader   *gzip.Reader
	done     bool
	filename string
}

func init() {
	Registrations = append(Registrations, Registration{
		MatchFileHeader: func(_ string, headerBytes []byte) bool {
			return bytes.HasPrefix(headerBytes, []byte{0x1f, 0x8b})
		},
		GetDecoder: GetGzDecoder,
	})
}

func GetGzDecoder(filename string, reader io.Reader) (Decoder, error) {
	gzipReader, err := gzip.NewReader(reader)
	if err != nil {
		return nil, err
	}
	return &GzDecoder{
		done:     false,
		reader:   gzipReader,
		filename: filename,
	}, nil
}

func (d *GzDecoder) Read(p []byte) (int, error) {
	return d.reader.Read(p)
}

func (d *GzDecoder) Next() (*Entry, error) {
	if d.done {
		return nil, io.EOF
	}
	d.done = true
	return &Entry{
		Filename: strings.TrimSuffix(d.filename, ".gz"),
		Type:     "file",
	}, nil
}
