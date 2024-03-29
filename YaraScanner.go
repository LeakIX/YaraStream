package YaraStream

import (
	"github.com/hillu/go-yara/v4"
	"io/fs"
	"log"
	"os"
	"path/filepath"
)

type YaraScanner struct {
	rules *yara.Rules
}

type RuleDirectory struct {
	Namespace string
	Path      string
}

// NewYaraScanner Will return a new scanner with rules compiled
func NewYaraScanner(ruleDirectories ...RuleDirectory) (*YaraScanner, error) {
	scanner := &YaraScanner{}
	compiler, err := yara.NewCompiler()
	if err != nil {
		return nil, err
	}
	for _, ruleDirectory := range ruleDirectories {
		err = scanner.addDirectory(compiler, ruleDirectory)
		if err != nil {
			return nil, err
		}
	}
	if scanner.rules, err = compiler.GetRules(); err != nil {
		return nil, err
	}
	return scanner, nil
}

func (s *YaraScanner) addDirectory(compiler *yara.Compiler, ruleDirectory RuleDirectory) error {
	return filepath.Walk(ruleDirectory.Path, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && (filepath.Ext(path) == ".yar" || filepath.Ext(path) == ".yara") {
			ruleFile, err := os.Open(path)
			if err != nil {
				return err
			}
			err = compiler.AddFile(ruleFile, ruleDirectory.Namespace)
			if err != nil {
				return err
			}
			log.Printf("Loaded %s in namespace %s", path, ruleDirectory.Namespace)
		}
		return nil
	})
}
