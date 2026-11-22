package securityanalysis

import (
    "errors"
    "fmt"
    "regexp"
    "sort"
    "strings"
)

// STARTEnvelope is a lossless, candidate-only export matching the existing
// START_REAF_INPUT_V0.1 contract from START_REAF_INTEGRATION_001_20261019.
// Creation never executes the REAF engine or grants any external authority.
type STARTEnvelope struct {
    ProjectID string `json:"project_id"`
    Namespace string `json:"namespace"`
    Purpose string `json:"purpose"`
    Sources []string `json:"sources"`
    Authority STARTAuthority `json:"authority"`
    Primitives []STARTAtom `json:"primitives"`
}
type STARTAuthority struct { ExecuteExternal bool `json:"execute_external"` }
type STARTAtom struct {
    ID string `json:"id"`
    Type string `json:"type"`
    CanonicalID string `json:"canonical_id"`
    Namespace string `json:"namespace"`
    Context string `json:"context"`
    Value any `json:"value"`
    Provenance STARTProvenance `json:"provenance"`
}
type STARTProvenance struct { Source string `json:"source"` }

var namespaceID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

func ProjectSTART(r Report, projectID, namespace string)(STARTEnvelope,error){
    projectID, namespace = strings.TrimSpace(projectID),strings.TrimSpace(namespace)
    if !namespaceID.MatchString(projectID) || !namespaceID.MatchString(namespace) {
        return STARTEnvelope{},errors.New("project_id and namespace must be bounded non-empty identifiers")
    }
    projection,err:=ProjectU8PI(r)
    if err!=nil{return STARTEnvelope{},err}
    sourceRef:="sha256:"+r.SourceSHA256
    context:="security.analysis/"+r.Tool+"; source origin unverified; staging only"
    out:=STARTEnvelope{ProjectID:projectID,Namespace:namespace,
        Purpose:"Stage offline security analysis observations for existing START/REAF (no execution)",
        Sources:[]string{sourceRef},Authority:STARTAuthority{ExecuteExternal:false},
        Primitives:make([]STARTAtom,0,len(projection.Nodes)+len(projection.Relations))}
    seen:=map[string]struct{}{}
    appendAtom:=func(atom STARTAtom)error{
        if _,found:=seen[atom.ID];found{return fmt.Errorf("duplicate primitive id: %s",atom.ID)}
        seen[atom.ID]=struct{}{}
        out.Primitives=append(out.Primitives,atom)
        return nil
    }
    for _,n:=range projection.Nodes{
        atom:=STARTAtom{ID:n.ID,Type:n.Primitive,CanonicalID:n.ID,
            Namespace:namespace,Context:context,
            Value:map[string]string{"kind":n.Kind,"status":n.Status,"value":n.Value},
            Provenance:STARTProvenance{Source:sourceRef}}
        if err:=appendAtom(atom);err!=nil{return STARTEnvelope{},err}
    }
    for _,e:=range projection.Relations{
        atom:=STARTAtom{ID:e.ID,Type:"P4",CanonicalID:e.ID,
            Namespace:namespace,Context:context,
            Value:map[string]string{"from":e.From,"to":e.To,"predicate":e.Predicate},
            Provenance:STARTProvenance{Source:sourceRef}}
        if err:=appendAtom(atom);err!=nil{return STARTEnvelope{},err}
    }
    sort.Slice(out.Primitives,func(i,j int)bool{return out.Primitives[i].ID<out.Primitives[j].ID})
    return out,nil
}
