package main

import (
	"fmt"
	"strconv"
)

// validateID converts a raw string to a positive integer.
//
// strconv.Atoi is a Cap::all() sanitiser in Nyx's Go label rules.
// Any tainted string that passes through this function has all taint
// capabilities neutralised — the returned int carries no taint.
func validateID(raw string) (int, error) {
	id, err := strconv.Atoi(raw)
	if err != nil || id <= 0 {
		return 0, fmt.Errorf("invalid id: %q", raw)
	}
	return id, nil
}
