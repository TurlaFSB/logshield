package engine

import (
	"strings"
	"unicode"
)

// Log4j lower-cases lookup prefixes with Java's String.toLowerCase(Locale.US),
// and its ${lower:} and ${upper:} lookups use Java's case mapping too. Java uses
// Unicode "full" case mapping, which differs from Go's simple mapping in a few
// places that matter to an attacker building letters out of other characters.
// These helpers reproduce Java's behavior closely enough for that purpose.
//
// Assumed locale: not Turkic. Under a Turkish default locale Java maps 'I' to
// dotless i, which this code does not model.

const (
	runeCapitalIWithDot = rune(0x0130) // LATIN CAPITAL LETTER I WITH DOT ABOVE
	runeCombiningDot    = rune(0x0307) // COMBINING DOT ABOVE
)

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// javaLower mirrors String.toLowerCase(Locale.US).
func javaLower(s string) string {
	if isASCII(s) {
		return strings.ToLower(s)
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r == runeCapitalIWithDot {
			// Full mapping is "i" followed by a combining dot, not a bare "i".
			b.WriteByte('i')
			b.WriteRune(runeCombiningDot)
			continue
		}
		b.WriteRune(unicode.ToLower(r))
	}
	return b.String()
}

// javaUpper mirrors String.toUpperCase for the characters whose full mapping
// expands to several characters. Everything else follows the simple mapping,
// which already agrees with Java (for example dotless i and long s map to the
// ASCII letters I and S).
func javaUpper(s string) string {
	if isASCII(s) {
		return strings.ToUpper(s)
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch r {
		case 0x00DF: // sharp s
			b.WriteString("SS")
		case 0x0149: // n preceded by apostrophe
			b.WriteRune(0x02BC)
			b.WriteByte('N')
		case 0x01F0: // j with caron
			b.WriteByte('J')
			b.WriteRune(0x030C)
		case 0xFB00:
			b.WriteString("FF")
		case 0xFB01:
			b.WriteString("FI")
		case 0xFB02:
			b.WriteString("FL")
		case 0xFB03:
			b.WriteString("FFI")
		case 0xFB04:
			b.WriteString("FFL")
		case 0xFB05, 0xFB06:
			b.WriteString("ST")
		default:
			b.WriteRune(unicode.ToUpper(r))
		}
	}
	return b.String()
}
