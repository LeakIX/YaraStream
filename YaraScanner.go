package YaraStream

import (
	"github.com/hillu/go-yara/v4"
	"io/fs"
	"os"
	"path/filepath"
)

type YaraScanner struct {
	rules *yara.Rules
}

func NewYaraScanner(rulesPath string) (*YaraScanner, error) {
	scanner := &YaraScanner{}
	compiler, err := yara.NewCompiler()
	if err != nil {
		return nil, err
	}
	err = filepath.Walk(rulesPath, func(path string, info fs.FileInfo, err error) error {
		if !info.IsDir() && filepath.Ext(path) == ".yar" {
			ruleFile, err := os.Open(path)
			if err != nil {
				return err
			}
			err = compiler.AddFile(ruleFile, "main")
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if scanner.rules, err = compiler.GetRules(); err != nil {
		return nil, err
	}
	return scanner, nil
}
