package securityanalysis

import (
    "encoding/json"
    "testing"
)

func TestU8PIProjectionStableAndNoDanglingRelations(t *testing.T) {
    raw:=[]byte(`<nmaprun><host><address addr="192.0.2.10" addrtype="ipv4"/><ports><port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port></ports></host></nmaprun>`)
    report,err:=Parse("nmap",raw)
    if err!=nil {t.Fatal(err)}
    a,err:=ProjectU8PI(report)
    if err!=nil {t.Fatal(err)}
    b,err:=ProjectU8PI(report)
    if err!=nil {t.Fatal(err)}
    aJSON,_:=json.Marshal(a)
    bJSON,_:=json.Marshal(b)
    if string(aJSON)!=string(bJSON) {t.Fatal("projection is not deterministic")}
    if a.Provenance!="SOURCE_UNATTESTED" || len(a.Relations)!=8 {t.Fatalf("unexpected projection %+v",a)}
    nodes:=map[string]bool{}
    primitives:=map[string]bool{}
    for _,n:=range a.Nodes {nodes[n.ID]=true;primitives[n.Primitive]=true}
    for _,rel:=range a.Relations {
        primitives[rel.Primitive]=true
        if !nodes[rel.From] || !nodes[rel.To] {t.Fatal("dangling edge",rel)}
    }
    for _,p:=range []string{"P1","P2","P3","P4","P5","P6","P7","P8"} {if !primitives[p] {t.Fatal("missing primitive",p)}}
}

func TestProjectionRejectsTamperedID(t *testing.T){
    report,err:=Parse("zap",[]byte(`{"site":[{"@name":"https://example.test","alerts":[{"name":"Missing header","pluginid":"10021"}]}]}`))
    if err!=nil {t.Fatal(err)}
    report.Findings[0].ID="00000000000000000000000000000000"
    if _,err:=ProjectU8PI(report);err==nil{t.Fatal("accepted tampered finding ID")}
}
