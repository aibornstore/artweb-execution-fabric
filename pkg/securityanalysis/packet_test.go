package securityanalysis

import (
    "archive/zip"
    "bytes"
    "encoding/json"
    "testing"
)
func TestShadowPacketRoundTripDeterministic(t *testing.T) {
    report,err:=Parse("nmap",[]byte(`<nmaprun><host><address addr="192.0.2.10" addrtype="ipv4"/><ports><port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port></ports></host></nmaprun>`))
    if err!=nil{t.Fatal(err)}
    a,err:=SealPacket(report,"artweb-security","artweb.security")
    if err!=nil{t.Fatal(err)}
    b,err:=SealPacket(report,"artweb-security","artweb.security")
    if err!=nil{t.Fatal(err)}
    if !bytes.Equal(a,b){t.Fatal("packet bytes not deterministic")}
    receipt,err:=VerifyPacket(a)
    if err!=nil{t.Fatal(err)}
    if receipt.Status!="INPUT_VALIDATED_SHADOW_ONLY" || receipt.ExternalExecution || receipt.FindingCount!=1 || receipt.PrimitiveCount<8{
        t.Fatalf("wrong receipt: %+v",receipt)
    }
    if receipt.PacketSHA256!=sha256Hex(a){t.Fatal("packet sha mismatch")}
}
func TestShadowPacketRejectsTamperingAndExtraFiles(t *testing.T){
    report,err:=Parse("zap",[]byte(`{"site":[{"@name":"https://example.test","alerts":[{"name":"Missing header","riskcode":"2","pluginid":"10021"}]}]}`))
    if err!=nil{t.Fatal(err)}
    original,err:=SealPacket(report,"artweb-security","artweb.security")
    if err!=nil{t.Fatal(err)}
    raw:=append([]byte(nil),original...)
    raw[len(raw)/3]^=0x01
    if _,err:=VerifyPacket(raw);err==nil{t.Fatal("accepted bit flip")}
    buf:=new(bytes.Buffer)
    writer:=zip.NewWriter(buf)
    for _,p:=range []struct{name string;body []byte}{{"report.json",[]byte("x")},{"../escape",[]byte("x")}}{
        out,_:=writer.Create(p.name)
        out.Write(p.body)
    }
    writer.Close()
    if _,err:=VerifyPacket(buf.Bytes());err==nil{t.Fatal("accepted extra file or path escape")}
    if _,err:=SealPacket(report,"artweb-security","invalid namespace");err==nil{t.Fatal("accepted invalid namespace")}
    report.Findings[0].ID="00000000000000000000000000000000"
    if _,err:=SealPacket(report,"artweb-security","artweb.security");err==nil{t.Fatal("accepted tampered ID")}
}
func TestShadowPacketRecomputeRejectsModifiedManifest(t *testing.T){
    report,err:=Parse("tshark",[]byte(`[{"_source":{"layers":{"ip":{"ip.dst":"198.51.100.10"},"tcp":{"tcp.dstport":"443"}}}}]`))
    if err!=nil{t.Fatal(err)}
    raw,err:=SealPacket(report,"artweb-security","artweb.security")
    if err!=nil{t.Fatal(err)}
    zr,_:=zip.NewReader(bytes.NewReader(raw),int64(len(raw)))
    payloads:=map[string][]byte{}
    for _,f:=range zr.File{
        r,_:=f.Open()
        var b bytes.Buffer
        b.ReadFrom(r)
        r.Close()
        payloads[f.Name]=b.Bytes()
    }
    var m PacketManifest
    if err:=json.Unmarshal(payloads["manifest.json"],&m);err!=nil{t.Fatal(err)}
    m.Files[0].SHA256="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    payloads["manifest.json"],_=toJSON(m)
    buf:=new(bytes.Buffer)
    zw:=zip.NewWriter(buf)
    for _,f:=range zr.File{
        w,_:=zw.Create(f.Name)
        w.Write(payloads[f.Name])
    }
    zw.Close()
    if _,err:=VerifyPacket(buf.Bytes());err==nil{t.Fatal("accepted recomputed ZIP with bad manifest")}
}
