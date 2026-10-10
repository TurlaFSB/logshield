package engine

import "strings"

// ebcdicLabel reports whether a Content-Type charset names an EBCDIC code page.
// Java ships these, and a framework that honors the declared charset will turn
// EBCDIC bytes back into ASCII-looking text that a byte filter never sees.
func ebcdicLabel(charset string) bool {
	c := strings.ToLower(strings.TrimSpace(charset))
	switch {
	case strings.HasPrefix(c, "ebcdic"), strings.HasPrefix(c, "cp0"), strings.HasPrefix(c, "cp5"),
		strings.HasPrefix(c, "ibm0"), strings.HasPrefix(c, "ibm5"), strings.HasPrefix(c, "ibm-0"), strings.HasPrefix(c, "ibm-5"),
		c == "cp1047", c == "ibm1047", c == "ibm-1047", c == "cp037", c == "ibm037", c == "ibm-37", c == "cp37":
		return true
	}
	return false
}

// ebcdicTable maps the EBCDIC code points shared by the common variants
// (IBM037, IBM500, IBM1047) for letters, digits and the punctuation a lookup
// needs. Variants differ on a few brackets and bars; those are mapped as in
// IBM037 because an attacker only needs letters, digits and '$', '{', '}', ':'.
var ebcdicTable = func() [256]byte {
	var t [256]byte
	for i := range t {
		t[i] = '?'
	}
	set := func(start int, chars string) {
		for i := 0; i < len(chars); i++ {
			t[start+i] = chars[i]
		}
	}
	set(0x81, "abcdefghi")
	set(0x91, "jklmnopqr")
	set(0xA2, "stuvwxyz")
	set(0xC1, "ABCDEFGHI")
	set(0xD1, "JKLMNOPQR")
	set(0xE2, "STUVWXYZ")
	set(0xF0, "0123456789")
	set(0x40, " ")
	set(0x4B, ".<(+|&")
	set(0x5A, "!$*);")
	set(0x60, "-/")
	set(0x6B, ",%_>?")
	set(0x79, "`:#@'=\"")
	set(0xA1, "~")
	t[0xC0], t[0xD0], t[0xE0] = '{', '}', '\\'
	t[0xBA], t[0xBB], t[0xB0] = '[', ']', '^'
	t[0x0D], t[0x25], t[0x05] = '\r', '\n', '\t'
	return t
}()

// ebcdicToASCII converts s from EBCDIC. Unmapped bytes become '?'.
func ebcdicToASCII(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		b[i] = ebcdicTable[s[i]]
	}
	return string(b)
}

// charsetParam returns the charset parameter of Content-Type, or "".
func charsetParam(headers []Header) string {
	for _, h := range headers {
		if strings.EqualFold(h.Name, "Content-Type") {
			return headerParam(h.Value, "charset")
		}
	}
	return ""
}
