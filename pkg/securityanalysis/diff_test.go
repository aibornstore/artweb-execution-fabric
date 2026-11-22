package securityanalysis

import (
    "strings"
    "testing"
)
func TestCompareObservedNotRemediated(t *testing.T){
    old,err:=Parse("nmap",[]byte(`<nmaprun><host><address addr="192.0.2.10" addrtype="ipv4"/><ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port></ports></host></nmaprun>`))
    if err!=nil{t.Fatal(err)}
    newReport,err:=Parse("nmap",[]byte(`<nmaprun><host><address addr="192.0.2.10" addrtype="ipv4"/><ports><port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port></ports></host></nmaprun>`))
    if err!=nil{t.Fatal(err)}
    diff,err:=Compare(old,newReport)
    if err!=nil{t.Fatal(err)}
    if len(diff.Added)!=1 || len(diff.NoLongerObserved)!=1 || diff.Unchanged!=0{t.Fatalf("bad diff: %+v",diff)}
    if diff.Added[0].Target!="192.0.2.10:443/tcp" || diff.NoLongerObserved[0].Target!="192.0.2.10:22/tcp"{t.Fatalf("wrong findings: %+v",diff)}
    diff2,err:=Compare(old,newReport)
    if err!=nil || diff2.Added[0].ID!=diff.Added[0].ID{t.Fatal("nondeterministic")}
    _,err=Compare(old,Report{Schema:Schema,Tool:"zap",SourceSHA256:newReport.SourceSHA256})
    if err==nil{t.Fatal("accepted cross-tool comparison")}
}
func TestNmapUncertainAndIPv6(t *testing.T){
    report,err:=Parse("nmap",[]byte(`<nmaprun><host><address addr="2001:db8::1" addrtype="ipv6"/><ports><port protocol="udp" portid="53"><state state="open|filtered"/><service name="domain"/></port></ports></host></nmaprun>`))
    if err!=nil{t.Fatal(err)}
    if len(report.Findings)!=1 || report.Findings[0].Kind!="service_uncertain" || report.Findings[0].Target!="[2001:db8::1]:53/udp"{t.Fatalf("ambiguous state misclassified: %+v",report)}
}
func TestZapSecretsNotPersistedFromUnselectedFields(t *testing.T){
    input:=`{"site":[{"@name":"https://example.test/?token=secret","alerts":[{"name":"Header absent","riskcode":"1","instances":[{"uri":"https://u:pass@example.test/path?key=secret","requestHeader":"Authorization: secret","responseBody":"password=secret"}]}]}]}`
    report,err:=Parse("zap",[]byte(input))
    if err!=nil{t.Fatal(err)}
    if len(report.Findings)!=1 || report.Findings[0].Target!="https://example.test/path"{t.Fatalf("incorrect redaction: %+v",report)}
    if strings.Contains(report.Findings[0].Target,"secret"){t.Fatal("URL leaked secret")}
}
func TestCompareRejectsTamperedIdentity(t *testing.T){
    a,err:=Parse("zap",[]byte(`{"site":[{"@name":"https://example.test","alerts":[{"name":"Security header missing","riskcode":"1","pluginid":"1"}]}]}`))
    if err!=nil{t.Fatal(err)}
    b:=a
    b.Findings=append([]Finding(nil),a.Findings...)
    b.Findings[0].Title="forged"
    if _,err:=Compare(a,b);err==nil{t.Fatal("tampered identity accepted")}
}