// Package securityanalysis converts third-party analysis exports into stable,
// evidence-linked findings without running scanners or opening sockets.
package securityanalysis

import (
    "crypto/sha256"
    "encoding/hex"
    "encoding/json"
    "encoding/xml"
    "errors"
    "fmt"
    "net/url"
    "sort"
    "strconv"
    "strings"
)

const (
    Schema = "security.analysis/v1"
    MaxInputBytes = 16 << 20
    MaxFindings = 5000
)

type Finding struct {
    ID string `json:"id"`
    Tool string `json:"tool"`
    Kind string `json:"kind"`
    Target string `json:"target"`
    Title string `json:"title"`
    Severity string `json:"severity"`
    Detail string `json:"detail,omitempty"`
    RuleID string `json:"rule_id,omitempty"`
}
type Report struct {
    Schema string `json:"schema"`
    Tool string `json:"tool"`
    SourceSHA256 string `json:"source_sha256"`
    Findings []Finding `json:"findings"`
}

// Parse ingests an existing export; it NEVER starts a security scan.
// Request bodies, authentication material and URL queries are not persisted.
func Parse(tool string, raw []byte) (Report,error) {
    if len(raw)==0 || len(raw)>MaxInputBytes { return Report{},fmt.Errorf("input size must be 1..%d bytes",MaxInputBytes) }
    tool=strings.ToLower(strings.TrimSpace(tool))
    digest:=sha256.Sum256(raw)
    report:=Report{Schema:Schema,Tool:tool,SourceSHA256:hex.EncodeToString(digest[:]),Findings:[]Finding{}}
    var found []Finding
    var err error
    switch tool {
    case "nmap": found,err=parseNmap(raw)
    case "zap": found,err=parseZAP(raw)
    default: return Report{},fmt.Errorf("unsupported analyzer %q",tool)
    }
    if err!=nil { return Report{},err }
    if len(found)>MaxFindings { return Report{},fmt.Errorf("finding count exceeds %d",MaxFindings) }
    dedup:=make(map[string]Finding,len(found))
    for _,f:=range found {
        f.Tool=tool
        identity:=tool+"\x00"+f.Kind+"\x00"+f.Target+"\x00"+f.Title+"\x00"+f.RuleID
        sum:=sha256.Sum256([]byte(identity))
        f.ID=hex.EncodeToString(sum[:16])
        dedup[f.ID]=f
    }
    for _,f:=range dedup { report.Findings=append(report.Findings,f) }
    sort.Slice(report.Findings,func(i,j int)bool{return report.Findings[i].ID<report.Findings[j].ID})
    return report,nil
}

type nmapXML struct {
    XMLName xml.Name `xml:"nmaprun"`
    Hosts []struct{
        Addresses []struct{
            Addr string `xml:"addr,attr"`
            AddrType string `xml:"addrtype,attr"`
        } `xml:"address"`
        Names []struct{
            Name string `xml:"name,attr"`
        } `xml:"hostnames>hostname"`
        Ports []struct{
            Protocol string `xml:"protocol,attr"`
            PortID string `xml:"portid,attr"`
            State struct{
                State string `xml:"state,attr"`
            } `xml:"state"`
            Service struct {
                Name string `xml:"name,attr"`
                Product string `xml:"product,attr"`
                Version string `xml:"version,attr"`
            } `xml:"service"`
        } `xml:"ports>port"`
    } `xml:"host"`
}

func parseNmap(raw []byte)([]Finding,error){
    var doc nmapXML
    if err:=xml.Unmarshal(raw,&doc);err!=nil {return nil,fmt.Errorf("invalid Nmap XML: %w",err)}
    if doc.XMLName.Local!="nmaprun" {return nil,errors.New("not an Nmap XML export")}
    out:=[]Finding{}
    for _,h:=range doc.Hosts{
        host:=""
        for _,a:=range h.Addresses {
            if a.AddrType=="ipv4" || a.AddrType=="ipv6" {
                host=clean(a.Addr);break
            }
        }
        if host=="" && len(h.Names)!=0 {host=clean(h.Names[0].Name)}
        if host=="" {continue}
        for _,p:=range h.Ports{
            if p.State.State!="open" && p.State.State!="open|filtered" {continue}
            port,err:=strconv.Atoi(p.PortID)
            if err!=nil || port<1 || port>65535 {continue}
            proto:=strings.ToLower(p.Protocol)
            if proto!="tcp" && proto!="udp" && proto!="sctp" {continue}
            service:=clean(p.Service.Name)
            if service=="" {service="unknown"}
            detail:=clean(strings.TrimSpace(p.Service.Product+" "+p.Service.Version))
            kind:="service"
            if p.State.State=="open|filtered" {
                // Nmap cannot confirm that the service is open in this state.
                kind="service_uncertain"
            }
            targetHost:=host
            if strings.Contains(host,":") && !strings.HasPrefix(host,"["){targetHost="["+host+"]"}
            out=append(out,Finding{Kind:kind,Target:fmt.Sprintf("%s:%d/%s",targetHost,port,proto),Title:service,Severity:"info",Detail:detail})
            if len(out)>MaxFindings{return nil,fmt.Errorf("finding count exceeds %d",MaxFindings)}
        }
    }
    return out,nil
}

type zapDocument struct{
    Site []struct{
        Name string `json:"@name"`
        Alerts []struct{
            Alert string `json:"alert"`
            Name string `json:"name"`
            RiskCode json.RawMessage `json:"riskcode"`
            RiskDesc string `json:"riskdesc"`
            PluginID string `json:"pluginid"`
            Instances []struct{
                URI string `json:"uri"`
            } `json:"instances"`
        } `json:"alerts"`
    } `json:"site"`
}

func parseZAP(raw []byte)([]Finding,error){
    var doc zapDocument
    if err:=json.Unmarshal(raw,&doc);err!=nil{return nil,fmt.Errorf("invalid ZAP JSON: %w",err)}
    if doc.Site==nil{return nil,errors.New("not a ZAP JSON report: site array missing")}
    out:=[]Finding{}
    for _,site:=range doc.Site{
        for _,a:=range site.Alerts{
            title:=clean(a.Name)
            if title==""{title=clean(a.Alert)}
            if title==""{title="unnamed alert"}
            risk:=parseRisk(a.RiskCode,a.RiskDesc)
            targets:=[]string{safeURL(site.Name)}
            if len(a.Instances)!=0{
                targets=targets[:0]
                for _,instance:=range a.Instances{targets=append(targets,safeURL(instance.URI))}
            }
            for _,target:=range targets{
                if target==""{continue}
                out=append(out,Finding{Kind:"web_alert",Target:target,Title:title,Severity:risk,RuleID:clean(a.PluginID)})
                if len(out)>MaxFindings{return nil,fmt.Errorf("finding count exceeds %d",MaxFindings)}
            }
        }
    }
    return out,nil
}

func parseRisk(raw json.RawMessage,fallback string)string{
    var value string
    if err:=json.Unmarshal(raw,&value);err!=nil{
        var num int
        if json.Unmarshal(raw,&num)==nil{value=strconv.Itoa(num)}
    }
    switch value{
    case "0":return "info"
    case "1":return "low"
    case "2":return "medium"
    case "3":return "high"
    }
    prefix:=strings.ToLower(strings.TrimSpace(strings.Split(fallback," ")[0]))
    switch prefix{
    case "informational":return "info"
    case "low","medium","high":return prefix
    }
    return "unknown"
}

func safeURL(input string)string{
    u,err:=url.Parse(strings.TrimSpace(input))
    if err!=nil || (u.Scheme!="http" && u.Scheme!="https") || u.Host==""{return ""}
    u.RawQuery=""
    u.Fragment=""
    u.User=nil
    return clean(u.String())
}
func clean(s string)string{
    s=strings.Join(strings.Fields(s)," ")
    if len(s)>512{s=s[:512]}
    return s
}