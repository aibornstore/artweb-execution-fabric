package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/aibornstore/artweb-execution-fabric/pkg/securityanalysis"
)

func TestValidateStageOfflineRejectsBrokenEdgesAndNoOverwrite(t *testing.T) {
	dir:=t.TempDir()
	report,err:=securityanalysis.Parse("nmap",[]byte(`<nmaprun><host><address addr="192.0.2.10" addrtype="ipv4"/><ports><port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port></ports></host></nmaprun>`))
	if err!=nil{t.Fatal(err)}
	env,err:=securityanalysis.ProjectSTART(report,"artweb-test","artweb.security")
	if err!=nil{t.Fatal(err)}
	raw,err:=json.Marshal(env)
	if err!=nil{t.Fatal(err)}
	input:=filepath.Join(dir,"envelope.json")
	receipt:=filepath.Join(dir,"receipt.json")
	if err:=os.WriteFile(input,raw,0600);err!=nil{t.Fatal(err)}
	if err:=runValidateStage(input,receipt);err!=nil{t.Fatal(err)}
	if err:=runValidateStage(input,receipt);err==nil{t.Fatal("receipt overwritten")}
	for i:=range env.Primitives {
		if env.Primitives[i].Type=="P4" {
			v:=env.Primitives[i].Value.(map[string]string)
			v["from"]="urn:security-analysis:missing"
			break
		}
	}
	raw,err=json.Marshal(env)
	if err!=nil{t.Fatal(err)}
	if err:=os.WriteFile(input,raw,0600);err!=nil{t.Fatal(err)}
	if err:=runValidateStage(input,filepath.Join(dir,"bad-receipt.json"));err==nil{t.Fatal("dangling edge accepted")}
	if _,err:=os.Stat(filepath.Join(dir,"bad-receipt.json"));!os.IsNotExist(err){t.Fatal("bad receipt was written")}
}
