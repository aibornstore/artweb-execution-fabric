package main

import (
    "os"
    "path/filepath"
    "testing"
)

func TestOfflineIngestNoOverwrite(t *testing.T){
    dir:=t.TempDir()
    source:=filepath.Join(dir,"nmap.xml")
    output:=filepath.Join(dir,"findings.json")
    if err:=os.WriteFile(source,[]byte(`<nmaprun><host><address addr="127.0.0.1" addrtype="ipv4"/><ports><port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port></ports></host></nmaprun>`),0600);err!=nil{t.Fatal(err)}
    if err:=run("nmap",source,output);err!=nil{t.Fatal(err)}
    out,err:=os.ReadFile(output)
    if err!=nil || len(out)==0{t.Fatal("missing output",err)}
    if err:=run("nmap",source,output);err==nil{t.Fatal("overwrote output")}
}

func TestOfflineDeltaNoOverwrite(t *testing.T){
    dir:=t.TempDir()
    src:=filepath.Join(dir,"nmap.xml")
    prev:=filepath.Join(dir,"prev.json")
    curr:=filepath.Join(dir,"current.json")
    delta:=filepath.Join(dir,"delta.json")
    if err:=os.WriteFile(src,[]byte(`<nmaprun><host><address addr="192.0.2.10" addrtype="ipv4"/><ports><port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port></ports></host></nmaprun>`),0600);err!=nil{t.Fatal(err)}
    if err:=run("nmap",src,prev);err!=nil{t.Fatal(err)}
    if err:=run("nmap",src,curr);err!=nil{t.Fatal(err)}
    if err:=runDiff(prev,curr,delta);err!=nil{t.Fatal(err)}
    if err:=runDiff(prev,curr,delta);err==nil{t.Fatal("overwrote delta")}
}