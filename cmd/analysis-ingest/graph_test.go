package main

import (
    "os"
    "path/filepath"
    "testing"
)
func TestOfflineTSharkGraphAndExclusive(t *testing.T) {
    dir:=t.TempDir()
    source:=filepath.Join(dir,"packets.json")
    report:=filepath.Join(dir,"report.json")
    graph:=filepath.Join(dir,"graph.json")
    raw:=[]byte(`[{"_source":{"layers":{"ip":{"ip.dst":"192.0.2.10"},"tcp":{"tcp.dstport":"443"}}}}]`)
    if err:=os.WriteFile(source,raw,0600);err!=nil{t.Fatal(err)}
    if err:=run("tshark",source,report);err!=nil{t.Fatal(err)}
    if err:=runGraph(report,graph);err!=nil{t.Fatal(err)}
    if err:=runGraph(report,graph);err==nil{t.Fatal("existing graph was overwritten")}
}
