package securityanalysis

import (
    "strings"
    "testing"
)
func TestNmapStableAndClosedFiltered(t *testing.T){
    raw:=[]byte(`<nmaprun><host><address addr="192.0.2.10" addrtype="ipv4"/><ports><port protocol="tcp" portid="80"><state state="open"/><service name="http" product="nginx" version="1.2"/></port><port protocol="tcp" portid="22"><state state="closed"/><service name="ssh"/></port></ports></host></nmaprun>`)
    got,err:=Parse("nmap",raw)
    if err!=nil{t.Fatal(err)}
    if len(got.Findings)!=1{t.Fatalf("expected 1 finding, got %#v",got.Findings)}
    f:=got.Findings[0]
    if f.Target!="192.0.2.10:80/tcp" || f.Title!="http" || f.Detail!="nginx 1.2"{t.Fatalf("unexpected finding: %#v",f)}
    again,err:=Parse("nmap",raw)
    if err!=nil || f.ID!=again.Findings[0].ID{t.Fatal("ID is not deterministic")}
}
func TestZAPRedactsQueryAndRequestBodies(t *testing.T){
    raw:=[]byte(`{"site":[{"@name":"https://example.test","alerts":[{"name":"Missing security header","riskcode":"2","pluginid":"10021","instances":[{"uri":"https://example.test/a?token=secret","requestHeader":"Authorization: Bearer secret"}]}]}]}`)
    got,err:=Parse("zap",raw)
    if err!=nil{t.Fatal(err)}
    if len(got.Findings)!=1 || got.Findings[0].Severity!="medium" || got.Findings[0].Target!="https://example.test/a"{t.Fatalf("unexpected: %#v",got)}
    if strings.Contains(strings.Join([]string{got.Findings[0].Target,got.Findings[0].Title,got.Findings[0].Detail}," "),"secret"){t.Fatal("secret leaked")}
}
func TestRejectMalformedAndOversize(t *testing.T){
    if _,err:=Parse("zap",[]byte(`{"not_zap":1}`));err==nil{t.Fatal("accepted non-ZAP JSON")}
    if _,err:=Parse("nmap",[]byte(`<nmaprun>`));err==nil{t.Fatal("accepted truncated XML")}
    if _,err:=Parse("nmap",make([]byte,MaxInputBytes+1));err==nil{t.Fatal("accepted oversize")}
}