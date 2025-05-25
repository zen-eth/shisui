package state

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v2"
)

type TestCase struct {
	BlockHeader           string `yaml:"block_header"`
	ContentKey            string `yaml:"content_key"`
	ContentValueOffer     string `yaml:"content_value_offer"`
	ContentValueRetrieval string `yaml:"content_value_retrieval"`
}

func getTestCases(filename string) ([]TestCase, error) {
	file, err := os.ReadFile(fmt.Sprintf("./testdata/%s", filename))
	if err != nil {
		return nil, err
	}
	res := make([]TestCase, 0)
	err = yaml.Unmarshal(file, &res)
	if err != nil {
		return nil, err
	}
	return res, nil
}
