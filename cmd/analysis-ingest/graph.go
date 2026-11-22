package main

import (
    "encoding/json"
    "errors"
    "os"

    "github.com/aibornstore/artweb-execution-fabric/pkg/securityanalysis"
)

func runGraph(input, output string) error {
    info, err := os.Stat(input)
    if err != nil { return err }
    if !info.Mode().IsRegular() || info.Size() > securityanalysis.MaxInputBytes {
        return errors.New("normalized report must be a regular bounded file")
    }
    raw, err := os.ReadFile(input)
    if err != nil { return err }
    var r securityanalysis.Report
    if err := json.Unmarshal(raw, &r); err != nil { return err }
    graph, err := securityanalysis.ProjectU8PI(r)
    if err != nil { return err }
    return writeExclusive(output, graph)
}
