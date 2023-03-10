package decoder

import (
	"bytes"
	"github.com/krolaw/zipstream"
	"io"
	"strings"
)

func init() {
	Registrations = append(Registrations, Registration{
		MatchFileHeader: func(_ string, headerBytes []byte) bool {
			return bytes.HasPrefix(headerBytes, []byte("PK\x03\x04"))
		},
		GetDecoder: GetZipDecoder,
	})
}

type ZipDecoder struct {
	reader *zipstream.Reader
}

func GetZipDecoder(_ string, reader io.Reader) (Decoder, error) {
	return &ZipDecoder{
		reader: zipstream.NewReader(reader),
	}, nil
}

func (d *ZipDecoder) Read(p []byte) (int, error) {
	return d.reader.Read(p)
}

func (d *ZipDecoder) Next() (*Entry, error) {
	header, err := d.reader.Next()
	if err != nil {
		return nil, err
	}
	fileEntry := &Entry{
		Filename: header.Name,
	}
	fileEntry.Type = "file"
	if strings.HasSuffix(fileEntry.Filename, "/") {
		fileEntry.Type = "dir"
	}
	return fileEntry, nil
}
