package main

import (
	"encoding/json"
	"errors"
	"os"

	"github.com/aibornstore/artweb-execution-fabric/pkg/securityanalysis"
)

func runValidateStage(input, output string) error {
	info, err := os.Stat(input)
	if err != nil { return err }
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > securityanalysis.MaxPacketBytes {
		return errors.New("stage input must be a bounded regular file")
	}
	raw, err := os.ReadFile(input)
	if err != nil { return err }
	var envelope securityanalysis.STARTEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil { return err }
	receipt, err := securityanalysis.ReadbackSTARTShadow(envelope)
	if err != nil { return err }
	return writeExclusive(output, receipt)
}
