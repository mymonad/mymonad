// internal/embed/weights.go
package embed

import (
	"path/filepath"
	"strings"
)

// SourceWeight defines a weight multiplier for files matching a pattern.
type SourceWeight struct {
	Pattern    string
	Multiplier float32
}

// DefaultWeights defines the default source weighting rules.
// Higher multiplier = more contribution to the monad.
// Order matters - first match wins.
var DefaultWeights = []SourceWeight{
	{"*.eml", 3.0},         // Email - high personal signal
	{"*/personal/*", 2.5},  // Personal folders
	{"*/diary/*", 2.5},     // Diary/journal
	{"*.md", 2.0},          // Long-form markdown
	{"*.txt", 1.5},         // Plain text notes
	{".bash_history", 0.3}, // Shell history - low signal
	{".zsh_history", 0.3},
	{".fish_history", 0.3},
	{"*", 1.0}, // Default
}

// GetWeight returns the weight multiplier for a file path.
// Uses DefaultWeights rules, first match wins.
func GetWeight(path string) float32 {
	return GetWeightWithRules(path, DefaultWeights)
}

// GetWeightWithRules returns the weight using custom rules.
func GetWeightWithRules(path string, rules []SourceWeight) float32 {
	filename := filepath.Base(path)

	for _, rule := range rules {
		// Check if pattern matches filename or path
		if matched, _ := filepath.Match(rule.Pattern, filename); matched {
			return rule.Multiplier
		}
		// Also check against full path for directory patterns
		if strings.Contains(rule.Pattern, "/") {
			if matched, _ := filepath.Match(rule.Pattern, path); matched {
				return rule.Multiplier
			}
			// Check if pattern substring exists in path
			patternPart := strings.Trim(rule.Pattern, "*")
			if strings.Contains(path, patternPart) {
				return rule.Multiplier
			}
		}
	}

	return 1.0 // Default weight
}
