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

func TestCompareChangedFindingProperties(t *testing.T){
    cases:=[]struct{
        tool,before,after,oldValue,newValue string
    }{
        {"nmap", `<nmaprun><host><address addr="192.0.2.10" addrtype="ipv4"/><ports><port protocol="tcp" portid="443"><state state="open"/><service name="https" product="nginx" version="1.20"/></port></ports></host></nmaprun>`, `<nmaprun><host><address addr="192.0.2.10" addrtype="ipv4"/><ports><port protocol="tcp" portid="443"><state state="open"/><service name="https" product="nginx" version="1.24"/></port></ports></host></nmaprun>`, "nginx 1.20", "nginx 1.24"},
        {"zap", `{"site":[{"@name":"https://example.test","alerts":[{"name":"Missing security header","riskcode":"1","pluginid":"10021"}]}]}`, `{"site":[{"@name":"https://example.test","alerts":[{"name":"Missing security header","riskcode":"3","pluginid":"10021"}]}]}`, "low", "high"},
        {"tshark", `[{"_source":{"layers":{"ip":{"ip.dst":"192.0.2.10"},"tcp":{"tcp.dstport":"443"}}}}]`, `[{"_source":{"layers":{"ip":{"ip.dst":"192.0.2.10"},"tcp":{"tcp.dstport":"443"}}}},{"_source":{"layers":{"ip":{"ip.dst":"192.0.2.10"},"tcp":{"tcp.dstport":"443"}}}}]`, "packet_count=1", "packet_count=2"},
    }
    for _,tc:=range cases{
        t.Run(tc.tool,func(t *testing.T){
            previous,err:=Parse(tc.tool,[]byte(tc.before));if err!=nil{t.Fatal(err)}
            current,err:=Parse(tc.tool,[]byte(tc.after));if err!=nil{t.Fatal(err)}
            result,err:=Compare(previous,current);if err!=nil{t.Fatal(err)}
            if len(result.Changed)!=1 || result.Unchanged!=0 || len(result.Added)!=0 || len(result.NoLongerObserved)!=0{t.Fatalf("change was missed: %+v",result)}
            before,after:=result.Changed[0].Before,result.Changed[0].After
            if before.ID!=after.ID{t.Fatal("identity drift")}
            if tc.tool=="zap"{
                if before.Severity!=tc.oldValue || after.Severity!=tc.newValue{t.Fatal("severity change missed")}
            }else if before.Detail!=tc.oldValue || after.Detail!=tc.newValue{t.Fatal("detail change missed")}
        })
    }
}
