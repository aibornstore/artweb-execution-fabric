package securityanalysis

import (
    "crypto/sha256"
    "encoding/hex"
    "errors"
    "fmt"
    "sort"
)

// Delta describes differences in OBSERVATIONS, not remediation of vulnerabilities.
// Incomplete scans may cause findings to become unobserved without being fixed.
type Delta struct {
    Schema string `json:"schema"`
    Tool string `json:"tool"`
    PreviousSHA256 string `json:"previous_source_sha256"`
    CurrentSHA256 string `json:"current_source_sha256"`
    Added []Finding `json:"added"`
    NoLongerObserved []Finding `json:"no_longer_observed"`
    Unchanged int `json:"unchanged"`
}
const DeltaSchema="security.analysis-delta/v1"

func Compare(previous,current Report)(Delta,error){
    if err:=validateReport(previous);err!=nil{return Delta{},fmt.Errorf("previous: %w",err)}
    if err:=validateReport(current);err!=nil{return Delta{},fmt.Errorf("current: %w",err)}
    if previous.Tool!=current.Tool{return Delta{},errors.New("cannot compare reports from different tools")}
    d:=Delta{Schema:DeltaSchema,Tool:current.Tool,PreviousSHA256:previous.SourceSHA256,CurrentSHA256:current.SourceSHA256,
        Added:[]Finding{},NoLongerObserved:[]Finding{}}
    prior:=make(map[string]Finding,len(previous.Findings))
    after:=make(map[string]Finding,len(current.Findings))
    for _,f:=range previous.Findings{prior[f.ID]=f}
    for _,f:=range current.Findings{after[f.ID]=f}
    for id,f:=range after{
        if _,existed:=prior[id];existed{d.Unchanged++}else{d.Added=append(d.Added,f)}
    }
    for id,f:=range prior{if _,observed:=after[id];!observed{d.NoLongerObserved=append(d.NoLongerObserved,f)}}
    sort.Slice(d.Added,func(i,j int)bool{return d.Added[i].ID<d.Added[j].ID})
    sort.Slice(d.NoLongerObserved,func(i,j int)bool{return d.NoLongerObserved[i].ID<d.NoLongerObserved[j].ID})
    return d,nil
}
func validateReport(r Report)error{
    if r.Schema!=Schema || (r.Tool!="nmap" && r.Tool!="zap"){return errors.New("unsupported report schema or tool")}
    if len(r.SourceSHA256)!=64{return errors.New("missing source SHA-256")}
    if _,err:=hex.DecodeString(r.SourceSHA256);err!=nil{return errors.New("invalid source SHA-256")}
    if len(r.Findings)>MaxFindings{return errors.New("too many findings")}
    seen:=make(map[string]struct{},len(r.Findings))
    for _,f:=range r.Findings{
        if f.Tool!=r.Tool || f.Target=="" || f.Title=="" || f.Kind=="" || len(f.ID)!=32{return errors.New("malformed finding")}
        if _,err:=hex.DecodeString(f.ID);err!=nil{return errors.New("invalid finding id")}
        identity:=r.Tool+"\x00"+f.Kind+"\x00"+f.Target+"\x00"+f.Title+"\x00"+f.RuleID
        sum:=sha256.Sum256([]byte(identity))
        if hex.EncodeToString(sum[:16])!=f.ID{return errors.New("finding identity mismatch")}
        if _,ok:=seen[f.ID];ok{return errors.New("duplicate finding id")}
        seen[f.ID]=struct{}{}
    }
    return nil
}