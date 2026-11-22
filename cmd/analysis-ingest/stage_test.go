package main

import (
    "os"
    "path/filepath"
    "testing"
)
func TestStageCLIExclusive(t *testing.T){
    dir:=t.TempDir()
    source:=filepath.Join(dir,"nmap.xml")
    report:=filepath.Join(dir,"normalized.json")
    envelope:=filepath.Join(dir,"start-envelope.json")
    raw:=[]byte(`<nmaprun><host><address addr="192.0.2.11" addrtype="ipv4"/><ports><port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port></ports></host></nmaprun>`)
    if err:=os.WriteFile(source,raw,0600);err!=nil{t.Fatal(err)}
    if err:=run("nmap",source,report);err!=nil{t.Fatal(err)}
    if err:=runStage(report,"artweb-security-test","artweb.security",envelope);err!=nil{t.Fatal(err)}
    if err:=runStage(report,"artweb-security-test","artweb.security",envelope);err==nil{t.Fatal("overwrote envelope")}
}
