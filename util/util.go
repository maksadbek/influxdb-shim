package util

import "strings"

// cleanQuery makes query comparable
// it turns all strings to lowercase and trims all spaces
func CleanQuery(q string) string {
	return strings.Replace(strings.ToLower(strings.TrimSpace(q)), " ", "", -1)
}
