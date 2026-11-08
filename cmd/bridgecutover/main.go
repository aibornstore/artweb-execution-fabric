package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/aibornstore/artweb-execution-fabric/internal/cutover"
)

func fatal(err error) { fmt.Fprintln(os.Stderr, err); os.Exit(1) }
func writeJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: bridgecutover evidence|promote|show|profile")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "evidence":
		fatalIf(runEvidence(os.Args[2:]))
	case "promote":
		fatalIf(runPromote(os.Args[2:]))
	case "show":
		fatalIf(runShow(os.Args[2:]))
	case "profile":
		fatalIf(runProfile(os.Args[2:]))
	default:
		fmt.Fprintln(os.Stderr, "unknown command")
		os.Exit(2)
	}
}
func fatalIf(err error) {
	if err != nil {
		fatal(err)
	}
}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

func runPromote(args []string) error {
	fs := flag.NewFlagSet("promote", flag.ContinueOnError)
	state := fs.String("state", "", "routing state base path")
	machine := fs.String("machine", "", "machine id")
	project := fs.String("project", "GLOBAL", "project")
	capability := fs.String("capability", "", "capability")
	target := fs.String("target", "", "target")
	evidenceDir := fs.String("evidence-dir", "", "directory of JSON evidence")
	out := fs.String("out", "", "optional transition output file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	var raws [][]byte
	entries, err := os.ReadDir(*evidenceDir)
	if err != nil {
		return err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(strings.ToLower(e.Name()), ".json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(*evidenceDir, e.Name()))
		if err != nil {
			return err
		}
		raws = append(raws, b)
	}
	now := time.Now().UTC()
	key := cutover.Key{MachineID: *machine, Project: *project, Capability: *capability, Target: *target}
	p, err := cutover.Evaluate(raws, key, cutover.DefaultPolicy(), now)
	if err != nil {
		return err
	}
	raw, _ := json.Marshal(p)
	tr, err := cutover.Apply(*state, raw, now)
	if err != nil {
		return err
	}
	if *out != "" {
		b, _ := json.MarshalIndent(tr, "", "  ")
		if err := os.WriteFile(*out, b, 0600); err != nil {
			return err
		}
	}
	return writeJSON(map[string]any{"promotion": p, "transition": tr})
}
func runShow(args []string) error {
	fs := flag.NewFlagSet("show", flag.ContinueOnError)
	state := fs.String("state", "", "state")
	machine := fs.String("machine", "", "machine")
	project := fs.String("project", "GLOBAL", "project")
	capability := fs.String("capability", "", "capability")
	target := fs.String("target", "", "target")
	if err := fs.Parse(args); err != nil {
		return err
	}
	e, found, gen, err := cutover.Resolve(*state, cutover.Key{MachineID: *machine, Project: *project, Capability: *capability, Target: *target}, time.Now().UTC(), nil)
	if err != nil {
		return err
	}
	return writeJSON(map[string]any{"found": found, "generation": gen, "entry": e})
}
func runProfile(args []string) error {
	fs := flag.NewFlagSet("profile", flag.ContinueOnError)
	state := fs.String("state", "", "state")
	profile := fs.String("profile", "rdc-readonly-core-windows-v1", "profile")
	machine := fs.String("machine", "", "machine")
	project := fs.String("project", "GLOBAL", "project")
	var targets multiFlag
	fs.Var(&targets, "target", "capability=target; repeatable")
	if err := fs.Parse(args); err != nil {
		return err
	}
	m := map[string]string{}
	for _, x := range targets {
		parts := strings.SplitN(x, "=", 2)
		if len(parts) != 2 {
			return fmt.Errorf("bad target %q", x)
		}
		m[parts[0]] = parts[1]
	}
	r, err := cutover.EvaluateProfile(*state, *profile, *machine, *project, m, time.Now().UTC())
	if err != nil {
		return err
	}
	if err := writeJSON(r); err != nil {
		return err
	}
	if !r.RDCIndependent {
		os.Exit(4)
	}
	return nil
}
