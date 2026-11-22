package securityanalysis

import (
    "encoding/json"
    "strings"
    "testing"
)

func TestTSharkAggregatesDestinationsWithoutPayload(t *testing.T) {
    raw := []byte(`[
      {"_source":{"layers":{"frame":{"frame.number":"1"},"ip":{"ip.src":"192.0.2.10","ip.dst":"198.51.100.7"},"tcp":{"tcp.srcport":"51000","tcp.dstport":"443"},"http":{"http.request.uri":"/token?secret=do-not-leak"}}}},
      {"_source":{"layers":{"ip":{"ip.src":"192.0.2.11","ip.dst":"198.51.100.7"},"tcp":{"tcp.dstport":["443"]}}}},
      {"_source":{"layers":{"ipv6":{"ipv6.src":"2001:db8::1","ipv6.dst":"2001:db8::2"},"udp":{"udp.dstport":"53"},"dns":{"dns.qry.name":"sensitive.internal"}}}}
    ]`)
    report,err:=Parse("tshark",raw)
    if err!=nil {t.Fatal(err)}
    if len(report.Findings)!=2 {t.Fatalf("expected two endpoints, got %+v",report.Findings)}
    report2,err:=Parse("tshark",raw)
    if err!=nil {t.Fatal(err)}
    if report.Findings[0].ID!=report2.Findings[0].ID {t.Fatal("unstable IDs")}
    encoded,err:=json.Marshal(report)
    if err!=nil {t.Fatal(err)}
    if strings.Contains(string(encoded),"sensitive") || strings.Contains(string(encoded),"do-not-leak") || strings.Contains(string(encoded),"51000") {t.Fatal("payload or source port leaked")}
    seen:=map[string]string{}
    for _,f:=range report.Findings {seen[f.Target]=f.Detail; if f.Kind!="traffic_destination" {t.Fatal(f)} }
    if seen["198.51.100.7:443/tcp"]!="packet_count=2" || seen["[2001:db8::2]:53/udp"]!="packet_count=1" {t.Fatal(seen)}
}

func TestTSharkRejectsWrongInputAndBadPorts(t *testing.T) {
    if _,err:=Parse("tshark",[]byte(`{"_source":{"layers":{}}}`));err==nil{t.Fatal("accepted object instead of packet array")}
    if _,err:=Parse("tshark",[]byte(`[{}]`));err==nil{t.Fatal("accepted missing layers")}
    raw:=[]byte(`[{"_source":{"layers":{"ip":{"ip.dst":"192.0.2.3"},"tcp":{"tcp.dstport":"70000"}}}}]`)
    got,err:=Parse("tshark",raw)
    if err!=nil || len(got.Findings)!=0 {t.Fatalf("bad port was accepted: %+v %v",got,err)}
}
