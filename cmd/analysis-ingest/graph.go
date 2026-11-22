package main

import (
    "encoding/json"
    "errors"
    "os"

    "github.com/aibornstore/artweb-execution-fabric/pkg/securityanalysis"
)

func readNormalizedReport(input string) (securityanalysis.Report,error) {
    info, err := os.Stat(input)
    if err != nil { return securityanalysis.Report{},err }
    if !info.Mode().IsRegular() || info.Size() > securityanalysis.MaxInputBytes {
        return securityanalysis.Report{},errors.New("normalized report must be a regular bounded file")
    }
    raw, err := os.ReadFile(input)
    if err != nil {return securityanalysis.Report{},err}
    var r securityanalysis.Report
    if err := json.Unmarshal(raw, &r); err != nil {return securityanalysis.Report{},err}
    return r,nil
}

func runGraph(input, output string) error {
    r,err:=readNormalizedReport(input)
    if err!=nil{return err}
    graph, err := securityanalysis.ProjectU8PI(r)
    if err != nil { return err }
    return writeExclusive(output, graph)
}

func runStage(input, projectID, namespace, output string) error {
    r,err:=readNormalizedReport(input)
    if err!=nil{return err}
    envelope,err:=securityanalysis.ProjectSTART(r,projectID,namespace)
    if err!=nil{return err}
    return writeExclusive(output,envelope)
}
