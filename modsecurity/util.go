package modsecurity

// Truncate truncates s and appends ... if s is longer than max.
func truncate(s string, max int) string {
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}
