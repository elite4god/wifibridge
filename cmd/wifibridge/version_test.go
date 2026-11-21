package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

func TestVersionConsistency(t *testing.T) {
	// 1. Check Makefile
	makefileBytes, err := os.ReadFile("../../Makefile")
	if err != nil {
		t.Fatalf("failed to read Makefile: %v", err)
	}
	reMake := regexp.MustCompile(`(?m)^VERSION\s*\?=\s*([0-9]+\.[0-9]+\.[0-9]+)`)
	matchMake := reMake.FindStringSubmatch(string(makefileBytes))
	if len(matchMake) < 2 {
		t.Fatalf("could not find VERSION in Makefile")
	}
	makeVer := strings.TrimSpace(matchMake[1])
	if makeVer != Version {
		t.Errorf("Makefile version %q does not match main.Version %q", makeVer, Version)
	}

	// 2. Check packaging/DEBIAN/control
	controlBytes, err := os.ReadFile("../../packaging/DEBIAN/control")
	if err != nil {
		t.Fatalf("failed to read packaging/DEBIAN/control: %v", err)
	}
	reControl := regexp.MustCompile(`(?m)^Version:\s*([0-9]+\.[0-9]+\.[0-9]+)`)
	matchControl := reControl.FindStringSubmatch(string(controlBytes))
	if len(matchControl) < 2 {
		t.Fatalf("could not find Version in packaging/DEBIAN/control")
	}
	controlVer := strings.TrimSpace(matchControl[1])
	if controlVer != Version {
		t.Errorf("DEBIAN/control version %q does not match main.Version %q", controlVer, Version)
	}
}
