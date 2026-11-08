package cutover

import (
	"fmt"
	"time"
)

var ReadOnlyCoreV1 = []string{"system.info@1", "process.list@1", "fs.stat@1", "fs.list@1", "fs.read@1", "network.ping@1"}
var WindowsReadOnlyExtensionV1 = []string{"service.status@1"}
var CurrentBridgeMinimumV1 = []string{"host.status@1", "fs.read@1"}

func EvaluateProfile(path, profile, machineID, project string, targets map[string]string, now time.Time) (ProfileResult, error) {
	var capabilities []string
	switch profile {
	case "bridge-current-minimum-v1":
		capabilities = append(capabilities, CurrentBridgeMinimumV1...)
	case "rdc-readonly-core-v1":
		capabilities = append(capabilities, ReadOnlyCoreV1...)
	case "rdc-readonly-core-windows-v1":
		capabilities = append(capabilities, ReadOnlyCoreV1...)
		capabilities = append(capabilities, WindowsReadOnlyExtensionV1...)
	default:
		return ProfileResult{}, fmt.Errorf("unknown cutover profile %q", profile)
	}
	out := ProfileResult{Schema: ProfileSchema, GeneratedAt: now.UTC().Format(time.RFC3339Nano), Profile: profile, MachineID: machineID, Project: project, BridgePrimary: true, RDCIndependent: true, Decision: "BRIDGE_PRIMARY"}
	for _, capability := range capabilities {
		target := targets[capability]
		if target == "" {
			out.BridgePrimary = false
			out.RDCIndependent = false
			out.Decision = "RECOVERY_REQUIRED"
			out.Capabilities = append(out.Capabilities, ProfileCapability{Capability: capability, Route: RouteRecoveryFallback, Reason: "profile target not configured"})
			continue
		}
		e, _, _, err := Resolve(path, Key{MachineID: machineID, Project: project, Capability: capability, Target: target}, now, nil)
		if err != nil {
			return ProfileResult{}, err
		}
		out.Capabilities = append(out.Capabilities, ProfileCapability{Capability: capability, Target: target, Route: e.Route, Reason: e.Reason})
		if e.Route != RouteBridgePrimary && e.Route != RouteMaintenance {
			out.BridgePrimary = false
			out.RDCIndependent = false
			out.Decision = "RECOVERY_REQUIRED"
		}
	}
	return out, nil
}
