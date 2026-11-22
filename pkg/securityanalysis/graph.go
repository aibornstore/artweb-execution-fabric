package securityanalysis

import (
    "crypto/sha256"
    "encoding/hex"
    "fmt"
    "sort"
)

const GraphSchema = "security.analysis-u8pi-projection/v1"

// Projection is an offline *candidate* for the existing U8PI graph, never a
// canonical store or signed Bridge execution receipt. No graph DB is mutated.
type Projection struct {
    Schema string `json:"schema"`
    Tool string `json:"tool"`
    SourceSHA256 string `json:"source_sha256"`
    Provenance string `json:"provenance"`
    Nodes []PrimitiveNode `json:"nodes"`
    Relations []PrimitiveRelation `json:"relations"`
}
type PrimitiveNode struct {
    ID string `json:"id"`
    Primitive string `json:"primitive"`
    Kind string `json:"kind"`
    Value string `json:"value"`
    Status string `json:"status"`
}
type PrimitiveRelation struct {
    ID string `json:"id"`
    Primitive string `json:"primitive"`
    From string `json:"from"`
    To string `json:"to"`
    Predicate string `json:"predicate"`
}

func stableURN(parts ...string) string {
    joined := ""
    for _, p := range parts { joined += fmt.Sprintf("%d:%s",len(p),p) }
    sum := sha256.Sum256([]byte(joined))
    return "urn:security-analysis:"+hex.EncodeToString(sum[:16])
}

func ProjectU8PI(r Report) (Projection,error) {
    if err := validateReport(r); err!=nil { return Projection{}, err }
    out := Projection{Schema:GraphSchema,Tool:r.Tool,SourceSHA256:r.SourceSHA256,
        Provenance:"SOURCE_UNATTESTED",Nodes:[]PrimitiveNode{},Relations:[]PrimitiveRelation{}}
    seen := map[string]bool{}
    addNode := func(n PrimitiveNode) {
        if seen[n.ID] { return }
        seen[n.ID]=true
        out.Nodes=append(out.Nodes,n)
    }
    addRel := func(from,to,predicate string) {
        out.Relations=append(out.Relations,PrimitiveRelation{
            ID:stableURN("relation",from,to,predicate), Primitive:"P4",From:from,To:to,Predicate:predicate,
        })
    }
    source := stableURN("resource",r.Tool,r.SourceSHA256)
    report := stableURN("report",r.Tool,r.SourceSHA256)
    state := stableURN("state",r.Tool,r.SourceSHA256,"source-unattested")
    action := stableURN("action",r.Tool,r.SourceSHA256,"local-projection")
    constraint := stableURN("constraint",r.Tool,r.SourceSHA256,"no-cutover")
    goal := stableURN("goal",r.Tool,r.SourceSHA256,"observe")
    addNode(PrimitiveNode{source,"P5","scanner_export_sha256",r.SourceSHA256,"UNATTESTED"})
    addNode(PrimitiveNode{report,"P8","analysis_report",r.Tool,"OBSERVED"})
    addNode(PrimitiveNode{state,"P2","source_verification","UNVERIFIED","ACTIVE"})
    addNode(PrimitiveNode{action,"P3","offline_projection","projection_only","DECLARED"})
    addNode(PrimitiveNode{constraint,"P6","execution_boundary","must_not_promote_bridge","ACTIVE"})
    addNode(PrimitiveNode{goal,"P7","analysis_goal","record_observations","DECLARED"})
    addRel(report,source,"derived_from")
    addRel(report,state,"has_source_state")
    addRel(action,report,"produced_projection_from")
    addRel(action,constraint,"subject_to")
    addRel(action,goal,"serves")
    for _,f := range r.Findings {
        target:=stableURN("target",f.Target)
        occurrence:=stableURN("finding_occurrence",r.Tool,r.SourceSHA256,f.ID)
        addNode(PrimitiveNode{target,"P1","analysis_target",f.Target,"OBSERVED"})
        addNode(PrimitiveNode{occurrence,"P8","observation",f.ID,"UNVERIFIED"})
        addRel(report,occurrence,"contains_observation")
        addRel(occurrence,target,"observes_target")
        addRel(occurrence,state,"has_source_state")
    }
    sort.Slice(out.Nodes,func(i,j int)bool{return out.Nodes[i].ID<out.Nodes[j].ID})
    sort.Slice(out.Relations,func(i,j int)bool{return out.Relations[i].ID<out.Relations[j].ID})
    // Dangling relations fail closed, independently of generation order.
    for _,edge:=range out.Relations {
        if !seen[edge.From] || !seen[edge.To] {return Projection{},fmt.Errorf("dangling relation: %s",edge.ID)}
    }
    return out,nil
}
