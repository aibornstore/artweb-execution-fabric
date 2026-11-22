package securityanalysis

import (
    "encoding/json"
    "errors"
    "fmt"
    "net"
    "sort"
    "strconv"
    "strings"
)

// parseTShark imports Wireshark/TShark -T json packet exports. It deliberately
// ignores frame payload, DNS questions, HTTP fields, TLS names, and all source
// endpoint attributes. A destination seen in traffic is NOT an open port.
func parseTShark(raw []byte) ([]Finding, error) {
    var packets []struct {
        Source struct {
            Layers map[string]json.RawMessage `json:"layers"`
        } `json:"_source"`
    }
    if err := json.Unmarshal(raw, &packets); err != nil {
        return nil, fmt.Errorf("invalid TShark JSON: %w", err)
    }
    if packets == nil {
        return nil, errors.New("not a TShark -T json packet array")
    }
    observed := make(map[string]int)
    for i, packet := range packets {
        if packet.Source.Layers == nil {
            return nil, fmt.Errorf("packet %d: missing _source.layers", i)
        }
        layers := packet.Source.Layers
        address := ""
        for _, source := range []struct { layer, field string }{
            {"ip", "ip.dst"}, {"ipv6", "ipv6.dst"},
        } {
            if rawLayer, ok := layers[source.layer]; ok {
                if addr, ok := layerField(rawLayer, source.field); ok && net.ParseIP(addr) != nil {
                    address = addr
                    break
                }
            }
        }
        if address == "" { continue }
        protocol, destPort := "", ""
        for _, p := range []struct { layer, field string }{
            {"tcp", "tcp.dstport"}, {"udp", "udp.dstport"},
        } {
            if rawLayer, ok := layers[p.layer]; ok {
                if value, ok := layerField(rawLayer, p.field); ok {
                    port, err := strconv.Atoi(value)
                    if err == nil && port >= 1 && port <= 65535 {
                        protocol, destPort = p.layer, strconv.Itoa(port)
                        break
                    }
                }
            }
        }
        if protocol == "" { continue }
        if strings.Contains(address, ":") { address = "["+address+"]" }
        endpoint := address+":"+destPort+"/"+protocol
        observed[endpoint]++
        if len(observed) > MaxFindings {
            return nil, fmt.Errorf("TShark unique destination limit exceeded: %d", MaxFindings)
        }
    }
    keys := make([]string, 0, len(observed))
    for key := range observed { keys = append(keys, key) }
    sort.Strings(keys)
    out := make([]Finding, 0, len(keys))
    for _, key := range keys {
        out = append(out, Finding{
            Kind: "traffic_destination", Target: key,
            Title: "Observed packet destination", Severity: "info",
            Detail: fmt.Sprintf("packet_count=%d", observed[key]),
        })
    }
    return out, nil
}

// TShark can encode dissector fields as scalars or arrays of scalars.
// Nested objects (which may carry raw payloads) are never included.
func layerField(raw json.RawMessage, name string) (string, bool) {
    var layer map[string]json.RawMessage
    if err := json.Unmarshal(raw, &layer); err != nil { return "", false }
    rawValue, ok := layer[name]
    if !ok { return "", false }
    var value string
    if json.Unmarshal(rawValue, &value) == nil { return value, true }
    var values []string
    if json.Unmarshal(rawValue, &values) == nil && len(values) > 0 { return values[0], true }
    return "", false
}
