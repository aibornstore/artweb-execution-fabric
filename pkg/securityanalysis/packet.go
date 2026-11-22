package securityanalysis

import (
    "archive/zip"
    "bytes"
    "crypto/sha256"
    "encoding/hex"
    "encoding/json"
    "errors"
    "fmt"
    "io"
    "sort"
    "time"
)

// A Packet is a deterministic, standalone, offline staging artifact. It is
// deliberately NOT a native REAF DB transaction or an authenticated receipt.
const (
    PacketSchema         = "security.analysis-shadow-packet/v1"
    PacketReadbackSchema = "security.analysis-shadow-readback/v1"
    MaxPacketBytes       = 64 << 20
)

type PacketMember struct {
    Name   string `json:"name"`
    SHA256 string `json:"sha256"`
    Bytes  int    `json:"bytes"`
}
type PacketManifest struct {
    Schema       string         `json:"schema"`
    SourceSHA256 string         `json:"source_sha256"`
    ProjectID    string         `json:"project_id"`
    Namespace    string         `json:"namespace"`
    Trust        string         `json:"trust"`
    Files        []PacketMember `json:"files"`
}
type PacketReadback struct {
    Schema            string `json:"schema"`
    Status            string `json:"status"`
    PacketSHA256      string `json:"packet_sha256"`
    SourceSHA256      string `json:"source_sha256"`
    ProjectID         string `json:"project_id"`
    Namespace         string `json:"namespace"`
    FindingCount      int    `json:"finding_count"`
    PrimitiveCount    int    `json:"primitive_count"`
    RelationCount     int    `json:"relation_count"`
    ExternalExecution bool   `json:"external_execution"`
}
func sha256Hex(raw []byte) string { h := sha256.Sum256(raw); return hex.EncodeToString(h[:]) }
func toJSON(value any) ([]byte, error) {
    raw, err := json.MarshalIndent(value, "", "  ")
    if err != nil { return nil, err }
    return append(raw, '\n'), nil
}

// SealPacket records a normalized report, its exactly-derived U8PI projection
// and the original START/REAF staging envelope in an immutable ZIP artifact.
// The source export is NOT included; the included source hash is unverified.
func SealPacket(report Report, projectID, namespace string) ([]byte, error) {
    if err := validateReport(report); err != nil { return nil, err }
    graph, err := ProjectU8PI(report)
    if err != nil { return nil, err }
    envelope, err := ProjectSTART(report, projectID, namespace)
    if err != nil { return nil, err }
    if envelope.Authority.ExecuteExternal { return nil, errors.New("external execution is not permitted in shadow packet") }
    contents := map[string][]byte{}
    for _, item := range []struct {
        name string
        value any
    }{
        {"report.json", report}, {"graph.json", graph}, {"start-envelope.json", envelope},
    } {
        data, err := toJSON(item.value)
        if err != nil { return nil, err }
        if len(data) > MaxPacketBytes/2 { return nil, errors.New("oversized packet member") }
        contents[item.name] = data
    }
    manifest := PacketManifest{Schema: PacketSchema, ProjectID: envelope.ProjectID, Namespace: envelope.Namespace,
        SourceSHA256: report.SourceSHA256, Trust: "UNATTESTED_INPUT_SHADOW_ONLY", Files: []PacketMember{}}
    for name, raw := range contents {
        manifest.Files = append(manifest.Files, PacketMember{Name: name, SHA256: sha256Hex(raw), Bytes: len(raw)})
    }
    sort.Slice(manifest.Files, func(i, j int) bool { return manifest.Files[i].Name < manifest.Files[j].Name })
    data, err := toJSON(manifest)
    if err != nil { return nil, err }
    contents["manifest.json"] = data
    keys := []string{"graph.json", "manifest.json", "report.json", "start-envelope.json"}
    buf := new(bytes.Buffer)
    zw := zip.NewWriter(buf)
    for _, name := range keys {
        header := &zip.FileHeader{Name: name, Method: zip.Store}
        header.SetModTime(time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC))
        header.SetMode(0644)
        writer, err := zw.CreateHeader(header)
        if err != nil { zw.Close(); return nil, err }
        if _, err := writer.Write(contents[name]); err != nil { zw.Close(); return nil, err }
    }
    if err := zw.Close(); err != nil { return nil, err }
    if buf.Len() > MaxPacketBytes { return nil, errors.New("packet exceeds maximum size") }
    return buf.Bytes(), nil
}

// VerifyPacket performs an exact, independently reconstructed readback from
// the ZIP. It authenticates neither the scanner nor the external REAF runtime.
func VerifyPacket(payload []byte) (PacketReadback, error) {
    if len(payload) == 0 || len(payload) > MaxPacketBytes { return PacketReadback{}, errors.New("invalid packet size") }
    zr, err := zip.NewReader(bytes.NewReader(payload), int64(len(payload)))
    if err != nil { return PacketReadback{}, fmt.Errorf("invalid ZIP: %w", err) }
    if len(zr.File) != 4 { return PacketReadback{}, errors.New("packet must contain exactly four members") }
    expectedNames := map[string]bool{"graph.json": true, "manifest.json": true, "report.json": true, "start-envelope.json": true}
    contents := map[string][]byte{}
    for _, file := range zr.File {
        if !expectedNames[file.Name] || contents[file.Name] != nil || file.FileInfo().IsDir() || file.Mode().Type() != 0 {
            return PacketReadback{}, fmt.Errorf("unexpected, duplicate or nonregular packet member %q", file.Name)
        }
        if file.UncompressedSize64 > MaxPacketBytes/2 { return PacketReadback{}, errors.New("oversized packet member") }
        reader, err := file.Open()
        if err != nil { return PacketReadback{}, err }
        data, err := io.ReadAll(io.LimitReader(reader, MaxPacketBytes/2+1))
        closeErr := reader.Close()
        if err != nil { return PacketReadback{}, err }
        if closeErr != nil { return PacketReadback{}, closeErr }
        if len(data) > MaxPacketBytes/2 { return PacketReadback{}, errors.New("oversized member payload") }
        contents[file.Name] = data
    }
    var manifest PacketManifest
    if err := json.Unmarshal(contents["manifest.json"], &manifest); err != nil { return PacketReadback{}, err }
    if manifest.Schema != PacketSchema || manifest.Trust != "UNATTESTED_INPUT_SHADOW_ONLY" {
        return PacketReadback{}, errors.New("invalid packet schema or trust")
    }
    var report Report
    if err := json.Unmarshal(contents["report.json"], &report); err != nil { return PacketReadback{}, err }
    if report.SourceSHA256 != manifest.SourceSHA256 { return PacketReadback{}, errors.New("source SHA mismatch") }
    original, err := SealPacket(report, manifest.ProjectID, manifest.Namespace)
    if err != nil { return PacketReadback{}, err }
    if !bytes.Equal(payload, original) { return PacketReadback{}, errors.New("packet content does not match deterministic reconstruction") }
    graph, err := ProjectU8PI(report)
    if err != nil { return PacketReadback{}, err }
    envelope, err := ProjectSTART(report, manifest.ProjectID, manifest.Namespace)
    if err != nil { return PacketReadback{}, err }
    return PacketReadback{Schema: PacketReadbackSchema, Status: "INPUT_VALIDATED_SHADOW_ONLY",
        PacketSHA256: sha256Hex(payload), SourceSHA256: report.SourceSHA256,
        ProjectID: envelope.ProjectID, Namespace: envelope.Namespace,
        FindingCount: len(report.Findings), PrimitiveCount: len(envelope.Primitives), RelationCount: len(graph.Relations),
        ExternalExecution: envelope.Authority.ExecuteExternal}, nil
}
