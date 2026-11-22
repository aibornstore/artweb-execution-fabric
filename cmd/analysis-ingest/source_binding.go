package main

import (
    "bytes"
    "encoding/json"
    "errors"
    "io"
    "os"

    "github.com/aibornstore/artweb-execution-fabric/pkg/securityanalysis"
)

func readBoundedRegular(path string, maxBytes int64) ([]byte, error) {
    file, err := os.Open(path)
    if err != nil { return nil, err }
    defer file.Close()
    stat, err := file.Stat()
    if err != nil { return nil, err }
    if !stat.Mode().IsRegular() || stat.Size() <= 0 || stat.Size() > maxBytes {
        return nil, errors.New("input must be a nonempty bounded regular file")
    }
    data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
    if err != nil {return nil, err}
    if int64(len(data)) > maxBytes {return nil, errors.New("input grew past allowed size")}
    return data, nil
}

func runVerifySource(tool, sourcePath, packetPath, outputPath string) error {
    source, err := readBoundedRegular(sourcePath, securityanalysis.MaxInputBytes)
    if err != nil { return err }
    packet, err := readBoundedRegular(packetPath, securityanalysis.MaxPacketBytes)
    if err != nil { return err }
    receipt, err := securityanalysis.VerifyPacketSource(tool, source, packet)
    if err != nil { return err }
    return writeExclusive(outputPath, receipt)
}

func runValidateStageBound(reportPath, stagePath, outputPath string) error {
    report, err := readNormalizedReport(reportPath)
    if err != nil { return err }
    stageBytes, err := readBoundedRegular(stagePath, securityanalysis.MaxPacketBytes)
    if err != nil { return err }
    decoder := json.NewDecoder(bytes.NewReader(stageBytes))
    decoder.DisallowUnknownFields()
    var envelope securityanalysis.STARTEnvelope
    if err := decoder.Decode(&envelope); err != nil { return err }
    var trailing any
    if err := decoder.Decode(&trailing); err != io.EOF {
        if err == nil {return errors.New("trailing stage object rejected")}
        return err
    }
    receipt, err := securityanalysis.ValidateSTARTAgainstReport(report, envelope)
    if err != nil { return err }
    return writeExclusive(outputPath, receipt)
}
