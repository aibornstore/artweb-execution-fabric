package securityanalysis

import (
    "archive/zip"
    "bytes"
    "encoding/json"
    "errors"
    "fmt"
    "io"
)

const SourceReadbackSchema = "security.analysis-source-replay/v1"

// SourceReadback proves local reproducibility from supplied bytes,
// not independent scanner or REAF execution attestation.
type SourceReadback struct {
    Schema string `json:"schema"`
    Status string `json:"status"`
    Tool string `json:"tool"`
    SourceSHA256 string `json:"source_sha256"`
    PacketSHA256 string `json:"packet_sha256"`
    FindingCount int `json:"finding_count"`
    ExternalExecution bool `json:"external_execution"`
}

// VerifyPacketSource parses the original export again and requires its
// canonical normalized findings to match the sealed packet exactly.
func VerifyPacketSource(tool string, originalSource, packet []byte) (SourceReadback, error) {
    receipt, err := VerifyPacket(packet)
    if err != nil { return SourceReadback{}, fmt.Errorf("packet verification: %w", err) }
    replayed, err := Parse(tool, originalSource)
    if err != nil { return SourceReadback{}, fmt.Errorf("source replay: %w", err) }
    if replayed.SourceSHA256 != receipt.SourceSHA256 {
        return SourceReadback{}, errors.New("provided original source bytes differ from sealed source hash")
    }
    zr, err := zip.NewReader(bytes.NewReader(packet), int64(len(packet)))
    if err != nil { return SourceReadback{}, err }
    var sealedRaw []byte
    for _, member := range zr.File {
        if member.Name != "report.json" { continue }
        if member.UncompressedSize64 > MaxPacketBytes/2 { return SourceReadback{}, errors.New("oversized normalized report") }
        stream, openErr := member.Open()
        if openErr != nil { return SourceReadback{}, openErr }
        sealedRaw, err = io.ReadAll(io.LimitReader(stream, MaxPacketBytes/2+1))
        closeErr := stream.Close()
        if err != nil { return SourceReadback{}, err }
        if closeErr != nil { return SourceReadback{}, closeErr }
        break
    }
    if len(sealedRaw) == 0 { return SourceReadback{}, errors.New("normalized report not present") }
    reproducedRaw, err := toJSON(replayed)
    if err != nil { return SourceReadback{}, err }
    if !bytes.Equal(sealedRaw, reproducedRaw) {
        return SourceReadback{}, errors.New("sealed findings differ from repeated source parsing")
    }
    return SourceReadback{
        Schema: SourceReadbackSchema,
        Status: "SOURCE_BYTES_REPLAYED_LOCAL_ONLY",
        Tool: replayed.Tool,
        SourceSHA256: replayed.SourceSHA256,
        PacketSHA256: receipt.PacketSHA256,
        FindingCount: len(replayed.Findings),
        ExternalExecution: false,
    }, nil
}

const STARTBindingSchema = "security.analysis-start-report-binding/v1"

// ValidateSTARTAgainstReport binds the candidate START graph to the exact
// normalized report, rather than validating topology alone.
func ValidateSTARTAgainstReport(report Report, envelope STARTEnvelope) (STARTGuardReceipt, error) {
    if err := validateReport(report); err != nil { return STARTGuardReceipt{}, err }
    if err := ValidateSTARTShadow(envelope); err != nil { return STARTGuardReceipt{}, err }
    expected, err := ProjectSTART(report, envelope.ProjectID, envelope.Namespace)
    if err != nil { return STARTGuardReceipt{}, err }
    want, err := json.Marshal(expected)
    if err != nil { return STARTGuardReceipt{}, err }
    got, err := json.Marshal(envelope)
    if err != nil { return STARTGuardReceipt{}, err }
    if !bytes.Equal(want, got) {
        return STARTGuardReceipt{}, errors.New("envelope does not match deterministic report-derived START projection")
    }
    result, err := ReadbackSTARTShadow(envelope)
    if err != nil { return STARTGuardReceipt{}, err }
    result.Schema = STARTBindingSchema
    result.Status = "REPORT_BOUND_STRUCTURAL_ONLY"
    return result, nil
}
