package securityanalysis

import (
    "bytes"
    "encoding/json"
    "strings"
    "testing"
)

const sourceFixture = `<nmaprun><host><address addr="192.0.2.10" addrtype="ipv4"/><ports><port protocol="tcp" portid="443"><state state="open"/><service name="https" product="nginx" version="1.24"/></port></ports></host></nmaprun>`

func TestVerifyPacketSourceReproducesOriginal(t *testing.T) {
    src := []byte(sourceFixture)
    report, err := Parse("nmap", src)
    if err != nil { t.Fatal(err) }
    packet, err := SealPacket(report, "example-project", "example.security")
    if err != nil { t.Fatal(err) }
    receipt, err := VerifyPacketSource("nmap", src, packet)
    if err != nil { t.Fatal(err) }
    if receipt.Tool != "nmap" || receipt.SourceSHA256 != report.SourceSHA256 || receipt.FindingCount != 1 || receipt.ExternalExecution || receipt.Status != "SOURCE_BYTES_REPLAYED_LOCAL_ONLY" { t.Fatalf("unexpected receipt: %+v", receipt) }
}

func TestVerifyPacketSourceRejectsMismatchedInputs(t *testing.T) {
    report, err := Parse("nmap", []byte(sourceFixture))
    if err != nil { t.Fatal(err) }
    packet, err := SealPacket(report, "example-project", "example.security")
    if err != nil { t.Fatal(err) }
    for _, tc := range []struct{name, tool string; source, pkt []byte}{
        {"changed_source", "nmap", []byte(strings.Replace(sourceFixture, "1.24", "1.25", 1)), packet},
        {"wrong_tool", "tshark", []byte(sourceFixture), packet},
        {"empty_source", "nmap", nil, packet},
        {"tampered_packet", "nmap", []byte(sourceFixture), append(bytes.Clone(packet), 1)},
    } {
        t.Run(tc.name, func(t *testing.T) { if _, err := VerifyPacketSource(tc.tool, tc.source, tc.pkt); err == nil { t.Fatal("unexpected PASS") } })
    }
}

func TestSTARTBindingRejectsFabricatedButStructurallyValidGraph(t *testing.T) {
    report, err := Parse("nmap", []byte(sourceFixture))
    if err != nil { t.Fatal(err) }
    envelope, err := ProjectSTART(report, "example-project", "example.security")
    if err != nil { t.Fatal(err) }
    receipt, err := ValidateSTARTAgainstReport(report, envelope)
    if err != nil || receipt.Status != "REPORT_BOUND_STRUCTURAL_ONLY" { t.Fatal(receipt,err) }

    raw, _ := json.Marshal(envelope)
    var modified STARTEnvelope
    if err := json.Unmarshal(raw, &modified); err != nil { t.Fatal(err) }
    for i, atom := range modified.Primitives {
        if atom.Type == "P1" { modified.Primitives[i].Value = map[string]any{"kind":"analysis_target","status":"VERIFIED","value":"synthetic"}; break }
    }
    if err := ValidateSTARTShadow(modified); err != nil { t.Fatalf("structural guard changed unexpectedly: %v", err) }
    if _, err := ValidateSTARTAgainstReport(report, modified); err == nil { t.Fatal("fabricated observation accepted") }
    different, err := Parse("nmap", []byte(strings.Replace(sourceFixture,"1.24","1.25",1)))
    if err != nil {t.Fatal(err)}
    if _,err:=ValidateSTARTAgainstReport(different,envelope);err==nil { t.Fatal("different report accepted") }
}
