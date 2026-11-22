package main

import (
    "bytes"
    "encoding/json"
    "os"
    "path/filepath"
    "testing"

    "github.com/aibornstore/artweb-execution-fabric/pkg/securityanalysis"
)
func TestSourceReplayCLIFailClosed(t *testing.T) {
    dir:=t.TempDir()
    source:=filepath.Join(dir,"scan.xml")
    normalized:=filepath.Join(dir,"report.json")
    packet:=filepath.Join(dir,"packet.zip")
    output:=filepath.Join(dir,"source-receipt.json")
    original:=[]byte(`<nmaprun><host><address addr="192.0.2.12" addrtype="ipv4"/><ports><port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port></ports></host></nmaprun>`)
    if err:=os.WriteFile(source,original,0600);err!=nil{t.Fatal(err)}
    if err:=run("nmap",source,normalized);err!=nil{t.Fatal(err)}
    if err:=runSeal(normalized,"test-reaf","test.security",packet);err!=nil{t.Fatal(err)}
    if err:=runVerifySource("nmap",source,packet,output);err!=nil{t.Fatal(err)}
    if err:=runVerifySource("nmap",source,packet,output);err==nil{t.Fatal("overwrite allowed")}
    modified:=bytes.Replace(original,[]byte(`portid="443"`),[]byte(`portid="444"`),1)
    if err:=os.WriteFile(source,modified,0600);err!=nil{t.Fatal(err)}
    bad:=filepath.Join(dir,"bad-source-receipt.json")
    if err:=runVerifySource("nmap",source,packet,bad);err==nil{t.Fatal("changed source accepted")}
    if _,err:=os.Stat(bad);!os.IsNotExist(err){t.Fatal("bad receipt written")}
}

func TestBoundStageCLIRejectsFabricatedValue(t *testing.T) {
    dir:=t.TempDir()
    source:=filepath.Join(dir,"scan.xml")
    normalized:=filepath.Join(dir,"report.json")
    stage:=filepath.Join(dir,"stage.json")
    output:=filepath.Join(dir,"receipt.json")
    original:=[]byte(`<nmaprun><host><address addr="192.0.2.14" addrtype="ipv4"/><ports><port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port></ports></host></nmaprun>`)
    if err:=os.WriteFile(source,original,0600);err!=nil{t.Fatal(err)}
    if err:=run("nmap",source,normalized);err!=nil{t.Fatal(err)}
    if err:=runStage(normalized,"test-reaf","test.security",stage);err!=nil{t.Fatal(err)}
    if err:=runValidateStageBound(normalized,stage,output);err!=nil{t.Fatal(err)}
    envelopeRaw,err:=os.ReadFile(stage);if err!=nil{t.Fatal(err)}
    var envelope securityanalysis.STARTEnvelope
    if err:=json.Unmarshal(envelopeRaw,&envelope);err!=nil{t.Fatal(err)}
    for i:=range envelope.Primitives {
       if envelope.Primitives[i].Type=="P1" {
          envelope.Primitives[i].Value=map[string]any{"kind":"analysis_target","status":"ACTIVE","value":"tampered"}
          break
       }
    }
    tampered,_:=json.Marshal(envelope)
    if err:=os.WriteFile(stage,tampered,0600);err!=nil{t.Fatal(err)}
    bad:=filepath.Join(dir,"bad-receipt.json")
    if err:=runValidateStageBound(normalized,stage,bad);err==nil{t.Fatal("fabricated observation accepted")}
    if _,err:=os.Stat(bad);!os.IsNotExist(err){t.Fatal("bad receipt created")}
}
