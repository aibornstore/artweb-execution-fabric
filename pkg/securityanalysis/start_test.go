package securityanalysis

import (
    "encoding/json"
    "testing"
)
func TestSTARTStagingEnvelopeMatchesEightPrimitives(t *testing.T){
    r,err:=Parse("nmap",[]byte(`<nmaprun><host><address addr="192.0.2.3" addrtype="ipv4"/><ports><port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port></ports></host></nmaprun>`))
    if err!=nil{t.Fatal(err)}
    a,err:=ProjectSTART(r,"artweb-security-test","artweb.security.analysis")
    if err!=nil{t.Fatal(err)}
    b,err:=ProjectSTART(r,"artweb-security-test","artweb.security.analysis")
    if err!=nil{t.Fatal(err)}
    aJSON,_:=json.Marshal(a)
    bJSON,_:=json.Marshal(b)
    if string(aJSON)!=string(bJSON){t.Fatal("nondeterministic envelope")}
    if a.Authority.ExecuteExternal || len(a.Sources)!=1 || a.Sources[0]!="sha256:"+r.SourceSHA256{t.Fatal("invalid provenance or authority",a)}
    counts:=map[string]int{}
    ids:=map[string]bool{}
    for _,atom:=range a.Primitives{
        counts[atom.Type]++
        if atom.Namespace!=a.Namespace || atom.Provenance.Source!=a.Sources[0] || ids[atom.ID]{t.Fatal("namespace/provenance/id drift",atom)}
        ids[atom.ID]=true
    }
    for _,typ:=range []string{"P1","P2","P3","P4","P5","P6","P7","P8"}{if counts[typ]==0{t.Fatal("missing primitive",typ)}}
}
func TestSTARTRejectsInvalidNamespaceAndTampering(t *testing.T){
    r,err:=Parse("zap",[]byte(`{"site":[{"@name":"https://example.test","alerts":[{"name":"Missing header","pluginid":"1"}]}]}`))
    if err!=nil{t.Fatal(err)}
    if _,err:=ProjectSTART(r,"artweb","unsafe other");err==nil{t.Fatal("accepted unsafe namespace")}
    r.Findings[0].ID="00000000000000000000000000000000"
    if _,err:=ProjectSTART(r,"artweb","artweb.security");err==nil{t.Fatal("accepted altered finding")}
}
