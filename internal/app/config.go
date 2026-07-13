package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
)

const defaultConfigName = ".repo-guardian.json"

type fileConfig struct {
	Format             *string   `json:"format"`
	LargeFileThreshold *int64    `json:"large_file_threshold"`
	MinimumScore       *int      `json:"min_score"`
	FailOnRisk         *bool     `json:"fail_on_risk"`
	Exclude            *[]string `json:"exclude"`
	BestEffort         *bool     `json:"best_effort"`
}

func loadConfig(path string, required bool) (fileConfig, bool, error) {
	file, err := os.Open(path)
	if err != nil {
		if !required && errors.Is(err, os.ErrNotExist) {
			return fileConfig{}, false, nil
		}
		return fileConfig{}, false, fmt.Errorf("open configuration %q: %w", path, err)
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	var config *fileConfig
	if err := decoder.Decode(&config); err != nil {
		return fileConfig{}, false, fmt.Errorf("parse configuration %q: %w", path, err)
	}
	if config == nil {
		return fileConfig{}, false, fmt.Errorf("parse configuration %q: top-level value must be an object", path)
	}
	if err := ensureJSONEnd(decoder); err != nil {
		return fileConfig{}, false, fmt.Errorf("parse configuration %q: %w", path, err)
	}
	return *config, true, nil
}

func ensureJSONEnd(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("configuration must contain exactly one JSON object")
		}
		return err
	}
	return nil
}
