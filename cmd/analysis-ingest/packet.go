package main

import (
    "errors"
    "os"
    "path/filepath"
    "github.com/aibornstore/artweb-execution-fabric/pkg/securityanalysis"
)
func writeBinaryExclusive(output string,raw []byte) error{
    if err:=os.MkdirAll(filepath.Dir(output),0700);err!=nil{return err}
    f,err:=os.OpenFile(output,os.O_CREATE|os.O_EXCL|os.O_WRONLY,0600)
    if err!=nil{return err}
    ok:=false
    defer func(){f.Close();if !ok{os.Remove(output)}}()
    if _,err:=f.Write(raw);err!=nil{return err}
    if err:=f.Sync();err!=nil{return err}
    ok=true
    return nil
}
func runSeal(input,projectID,namespace,output string)error{
    report,err:=readNormalizedReport(input)
    if err!=nil{return err}
    payload,err:=securityanalysis.SealPacket(report,projectID,namespace)
    if err!=nil{return err}
    if err:=writeBinaryExclusive(output,payload);err!=nil{return err}
    // Readback from disk after fsync. On failure retain evidence for inspection.
    _,err=runVerifyPacketReadback(output)
    return err
}
func runVerifyPacketReadback(input string)(securityanalysis.PacketReadback,error){
    info,err:=os.Stat(input)
    if err!=nil{return securityanalysis.PacketReadback{},err}
    if !info.Mode().IsRegular() || info.Size()>securityanalysis.MaxPacketBytes{
        return securityanalysis.PacketReadback{},errors.New("packet must be a bounded regular file")
    }
    raw,err:=os.ReadFile(input)
    if err!=nil{return securityanalysis.PacketReadback{},err}
    return securityanalysis.VerifyPacket(raw)
}
func runVerifyPacket(input,output string)error{
    readback,err:=runVerifyPacketReadback(input)
    if err!=nil{return err}
    return writeExclusive(output,readback)
}
