package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"

	"github.com/aibornstore/artweb-execution-fabric/pkg/securityanalysis"
)

func runStageScoped(input, projectID, namespace, output string) error {
	report, err := readNormalizedReport(input)
	if err != nil {
		return err
	}
	env, err := securityanalysis.ProjectSTARTScoped(report, projectID, namespace)
	if err != nil {
		return err
	}
	return writeExclusive(output, env)
}

func runValidateStageScopedBound(reportPath, stagePath, output string) error {
	report, err := readNormalizedReport(reportPath)
	if err != nil {
		return err
	}
	raw, err := readBoundedRegular(stagePath, securityanalysis.MaxPacketBytes)
	if err != nil {
		return err
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	var env securityanalysis.STARTEnvelope
	if err := d.Decode(&env); err != nil {
		return err
	}
	var extra interface{}
	if err := d.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("trailing stage object rejected")
		}
		return err
	}
	receipt, err := securityanalysis.ValidateSTARTScopedAgainstReport(report, env)
	if err != nil {
		return err
	}
	return writeExclusive(output, receipt)
}
