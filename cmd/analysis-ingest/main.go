// analysis-ingest is a local, offline converter for pre-existing scan exports.
// It does not scan, open sockets, install software or modify the source file.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/aibornstore/artweb-execution-fabric/pkg/securityanalysis"
)

func main() {
	if len(os.Args) == 6 && os.Args[1] == "stage-scoped" {
		if err := runStageScoped(os.Args[2], os.Args[3], os.Args[4], os.Args[5]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) == 5 && os.Args[1] == "validate-stage-scoped-bound" {
		if err := runValidateStageScopedBound(os.Args[2], os.Args[3], os.Args[4]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) == 6 && os.Args[1] == "verify-source" {
		if err := runVerifySource(os.Args[2], os.Args[3], os.Args[4], os.Args[5]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) == 5 && os.Args[1] == "validate-stage-bound" {
		if err := runValidateStageBound(os.Args[2], os.Args[3], os.Args[4]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) == 4 && os.Args[1] == "validate-stage" {
		if err := runValidateStage(os.Args[2], os.Args[3]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) == 6 && os.Args[1] == "seal" {
		if err := runSeal(os.Args[2], os.Args[3], os.Args[4], os.Args[5]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) == 4 && os.Args[1] == "verify-packet" {
		if err := runVerifyPacket(os.Args[2], os.Args[3]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) == 6 && os.Args[1] == "stage" {
		if err := runStage(os.Args[2], os.Args[3], os.Args[4], os.Args[5]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) == 4 && os.Args[1] == "graph" {
		if err := runGraph(os.Args[2], os.Args[3]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) == 5 && os.Args[1] == "diff" {
		if err := runDiff(os.Args[2], os.Args[3], os.Args[4]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) != 4 {
		fmt.Fprintln(os.Stderr, "usage: analysis-ingest <nmap|zap|tshark> <source.xml|source.json> <output.json>\n       analysis-ingest diff <previous-report.json> <current-report.json> <delta.json>\n       analysis-ingest graph <report.json> <u8pi-projection.json>\n       analysis-ingest stage <report.json> <project-id> <namespace> <start-envelope.json>\n       analysis-ingest seal <report.json> <project-id> <namespace> <packet.zip>\n       analysis-ingest verify-packet <packet.zip> <receipt.json>\n       analysis-ingest verify-source <nmap|zap|tshark> <raw-export> <packet.zip> <receipt.json>\n       analysis-ingest validate-stage-bound <report.json> <start-envelope.json> <receipt.json>\n       analysis-ingest stage-scoped <report.json> <project-id> <namespace> <output.json>\n       analysis-ingest validate-stage-scoped-bound <report.json> <scoped-envelope.json> <receipt.json>")
		os.Exit(2)
	}
	if err := run(os.Args[1], os.Args[2], os.Args[3]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(tool, input, output string) error {
	source, err := os.Open(input)
	if err != nil {
		return err
	}
	defer source.Close()
	info, err := source.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("source must be a regular file")
	}
	if info.Size() > securityanalysis.MaxInputBytes {
		return errors.New("source exceeds maximum size")
	}
	raw, err := os.ReadFile(input)
	if err != nil {
		return err
	}
	report, err := securityanalysis.Parse(tool, raw)
	if err != nil {
		return err
	}
	return writeExclusive(output, report)
}

func runDiff(previous, current, output string) error {
	var a, b securityanalysis.Report
	for _, item := range []struct {
		path   string
		result *securityanalysis.Report
	}{{previous, &a}, {current, &b}} {
		info, err := os.Stat(item.path)
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.Size() > securityanalysis.MaxInputBytes {
			return errors.New("report must be a regular bounded file")
		}
		raw, err := os.ReadFile(item.path)
		if err != nil {
			return err
		}
		if err = json.Unmarshal(raw, item.result); err != nil {
			return fmt.Errorf("invalid normalized report: %w", err)
		}
	}
	delta, err := securityanalysis.Compare(a, b)
	if err != nil {
		return err
	}
	return writeExclusive(output, delta)
}

func writeExclusive(output string, result any) error {
	buf, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(output), 0700); err != nil {
		return err
	}
	f, err := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		f.Close()
		if !ok {
			os.Remove(output)
		}
	}()
	if _, err = f.Write(append(buf, '\n')); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	ok = true
	return nil
}
