package engine

import "strings"

const hexDigits = "0123456789ABCDEF"

// Defang makes attacker-controlled text safe to write to a log, an alert, or a
// terminal. The output is printable ASCII and never contains the two-character
// sequence "${", so a downstream Java logging pipeline cannot be made to
// evaluate it. The encoding is percent-style and reversible: '%', control and
// non-ASCII bytes become %XX, and a '{' directly after '$' becomes %7B.
//
// If max is positive and the result would be longer, it is cut and "..." is
// appended.
func Defang(s string, max int) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if max > 0 && b.Len() >= max {
			b.WriteString("...")
			break
		}
		c := s[i]
		switch {
		case c == '{' && i > 0 && s[i-1] == '$':
			b.WriteString("%7B")
		case c < 0x20 || c >= 0x7f || c == '%':
			b.WriteByte('%')
			b.WriteByte(hexDigits[c>>4])
			b.WriteByte(hexDigits[c&0x0f])
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}
