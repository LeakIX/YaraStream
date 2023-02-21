package decoder

import (
	"archive/tar"
	"io"
	"strings"
)

func init() {
	Registrations = append(Registrations, Registration{
		MatchFileHeader: func(filename string, _ []byte) bool {
			return strings.HasSuffix(filename, ".tar")
		},
		GetDecoder: GetTarDecoder,
	})
}

type TarDecoder struct {
	reader *tar.Reader
}

func GetTarDecoder(_ string, reader io.Reader) (Decoder, error) {
	return &TarDecoder{
		reader: tar.NewReader(reader),
	}, nil
}

func (d *TarDecoder) Read(p []byte) (int, error) {
	return d.reader.Read(p)
}

func (d *TarDecoder) Next() (*Entry, error) {
	header, err := d.reader.Next()
	if err != nil {
		return nil, err
	}
	entry := &Entry{
		Filename: header.Name,
	}
	switch header.Typeflag {
	case tar.TypeDir:
		entry.Type = "dir"
	case tar.TypeReg:
		entry.Type = "file"
	}
	return entry, nil
}
