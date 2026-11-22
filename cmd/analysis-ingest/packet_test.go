package main

import (
    "os"
    "path/filepath"
    "testing"
)
func TestSealCLIBoundedExclusiveAndReadback(t *testing.T){
    dir:=t.TempDir()
    source:=filepath.Join(dir,"nmap.xml")
    report:=filepath.Join(dir,"report.json")
    packet:=filepath.Join(dir,"shadow-packet.zip")
    receipt:=filepath.Join(dir,"readback.json")
    raw:=[]byte(`<nmaprun><host><address addr="192.0.2.10" addrtype="ipv4"/><ports><port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port></ports></host></nmaprun>`)
    if err:=os.WriteFile(source,raw,0600);err!=nil{t.Fatal(err)}
    if err:=run("nmap",source,report);err!=nil{t.Fatal(err)}
    if err:=runSeal(report,"artweb-security","artweb.security",packet);err!=nil{t.Fatal(err)}
    if err:=runVerifyPacket(packet,receipt);err!=nil{t.Fatal(err)}
    if err:=runSeal(report,"artweb-security","artweb.security",packet);err==nil{t.Fatal("seal overwrote existing packet")}
    if err:=runVerifyPacket(packet,receipt);err==nil{t.Fatal("verify overwrote existing receipt")}
}
