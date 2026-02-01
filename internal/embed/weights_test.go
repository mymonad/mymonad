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
