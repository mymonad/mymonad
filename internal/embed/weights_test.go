// internal/embed/weights_test.go
package embed

import "testing"

func TestGetWeight(t *testing.T) {
	tests := []struct {
		path     string
		expected float32
	}{
		{"/home/user/mail/important.eml", 3.0},
		{"/home/user/personal/diary.md", 2.5},
		{"/home/user/notes.md", 2.0},
		{"/home/user/random.txt", 1.5},
		{"/home/user/.bash_history", 0.3},
		{"/home/user/.zsh_history", 0.3},
		{"/home/user/.fish_history", 0.3},
		{"/home/user/unknown.xyz", 1.0},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			weight := GetWeight(tt.path)
			if weight != tt.expected {
				t.Errorf("GetWeight(%q) = %f, want %f", tt.path, weight, tt.expected)
			}
		})
	}
}

func TestGetWeightWithRules(t *testing.T) {
	t.Run("custom rules", func(t *testing.T) {
		rules := []SourceWeight{
			{"*.json", 5.0},
			{"*.yaml", 3.0},
			{"*", 0.5},
		}

		tests := []struct {
			path     string
			expected float32
		}{
			{"/config/settings.json", 5.0},
			{"/config/app.yaml", 3.0},
			{"/config/other.txt", 0.5},
		}

		for _, tt := range tests {
			weight := GetWeightWithRules(tt.path, rules)
			if weight != tt.expected {
				t.Errorf("GetWeightWithRules(%q) = %f, want %f", tt.path, weight, tt.expected)
			}
		}
	})

	t.Run("empty rules returns default", func(t *testing.T) {
		rules := []SourceWeight{}
		weight := GetWeightWithRules("/any/path/file.txt", rules)
		if weight != 1.0 {
			t.Errorf("GetWeightWithRules with empty rules = %f, want 1.0", weight)
		}
	})

	t.Run("diary pattern matches", func(t *testing.T) {
		rules := []SourceWeight{
			{"*/diary/*", 2.5},
			{"*", 1.0},
		}

		tests := []struct {
			path     string
			expected float32
		}{
			{"/home/user/diary/entry.txt", 2.5},
			{"/deep/path/to/diary/notes.md", 2.5},
			{"/home/user/other/file.txt", 1.0},
		}

		for _, tt := range tests {
			weight := GetWeightWithRules(tt.path, rules)
			if weight != tt.expected {
				t.Errorf("GetWeightWithRules(%q) = %f, want %f", tt.path, weight, tt.expected)
			}
		}
	})

	t.Run("invalid pattern is skipped", func(t *testing.T) {
		rules := []SourceWeight{
			{"[invalid", 5.0}, // Invalid glob pattern (unclosed bracket)
			{"*.txt", 2.0},
			{"*", 1.0},
		}

		weight := GetWeightWithRules("/path/to/file.txt", rules)
		if weight != 2.0 {
			t.Errorf("GetWeightWithRules with invalid pattern = %f, want 2.0", weight)
		}
	})
}
