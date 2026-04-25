package main

import (
	"fmt"
	"regexp"
)

// safeOnBothBranches validates user input on every return path.
//
// Both returns call validateFormat, which accepts only alphanumeric
// strings.  The transform on each path is identical (and identically
// sanitising), so a per-return-path summary records two entries whose
// joined transform preserves the validation on every branch.
//
// The per-return-path decomposition ensures the callee's "validated
// on both branches" fact survives the summary, and the caller does
// not lose it to an over-approximated union that might suggest an
// unsanitised path exists.
var alnum = regexp.MustCompile(`^[A-Za-z0-9]+$`)

func validateFormat(raw string) (string, error) {
	if !alnum.MatchString(raw) {
		return "", fmt.Errorf("invalid format: %q", raw)
	}
	return raw, nil
}

func safeOnBothBranches(raw string, preferStrict bool) (string, error) {
	if preferStrict {
		// Strict path: validate, then return.
		clean, err := validateFormat(raw)
		if err != nil {
			return "", err
		}
		return clean, nil
	}
	// Loose path: also validate, then return.  Same sanitiser.
	return validateFormat(raw)
}
