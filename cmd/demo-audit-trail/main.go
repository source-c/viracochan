// Demo: Audit Trail and Compliance
// Shows comprehensive audit logging, chain verification, and compliance reporting
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/source-c/viracochan"
)

type AuditEvent struct {
	Timestamp       time.Time              `json:"timestamp"`
	Actor           string                 `json:"actor"`
	Action          string                 `json:"action"`
	ConfigID        string                 `json:"config_id"`
	Version         uint64                 `json:"version"`
	Checksum        string                 `json:"checksum"`
	Changes         map[string]interface{} `json:"changes,omitempty"`
	Signature       string                 `json:"signature,omitempty"`
	Verified        bool                   `json:"verified"`
	ComplianceFlags map[string]bool        `json:"compliance_flags,omitempty"`
}

type AuditLog struct {
	Events  []AuditEvent
	storage viracochan.Storage
}

func NewAuditLog(storage viracochan.Storage) *AuditLog {
	return &AuditLog{
		Events:  []AuditEvent{},
		storage: storage,
	}
}

func (a *AuditLog) Record(event AuditEvent) error {
	a.Events = append(a.Events, event)

	// Persist to storage
	data, err := json.MarshalIndent(a.Events, "", "  ")
	if err != nil {
		return err
	}

	return a.storage.Write(context.Background(), "audit.log", data)
}

func (a *AuditLog) GenerateReport() string {
	var report strings.Builder

	report.WriteString("=== AUDIT REPORT ===\n")
	report.WriteString(fmt.Sprintf("Total Events: %d\n", len(a.Events)))
	report.WriteString(fmt.Sprintf("Period: %s to %s\n\n",
		a.Events[0].Timestamp.Format(time.RFC3339),
		a.Events[len(a.Events)-1].Timestamp.Format(time.RFC3339)))

	// Group by actor
	byActor := make(map[string][]AuditEvent)
	for _, event := range a.Events {
		byActor[event.Actor] = append(byActor[event.Actor], event)
	}

	report.WriteString("Activity by Actor:\n")
	for actor, events := range byActor {
		report.WriteString(fmt.Sprintf("  %s: %d actions\n", actor, len(events)))
	}

	// Compliance summary
	report.WriteString("\nCompliance Summary:\n")
	compliant := 0
	nonCompliant := 0
	for _, event := range a.Events {
		if event.Verified && allCompliant(event.ComplianceFlags) {
			compliant++
		} else {
			nonCompliant++
		}
	}
	report.WriteString(fmt.Sprintf("  Compliant: %d\n", compliant))
	report.WriteString(fmt.Sprintf("  Non-Compliant: %d\n", nonCompliant))

	return report.String()
}

func allCompliant(flags map[string]bool) bool {
	for _, v := range flags {
		if !v {
			return false
		}
	}
	return true
}

type ComplianceChecker struct {
	rules map[string]func(*viracochan.Config) bool
}

func NewComplianceChecker() *ComplianceChecker {
	return &ComplianceChecker{
		rules: map[string]func(*viracochan.Config) bool{
			"has_signature": func(cfg *viracochan.Config) bool {
				return cfg.Meta.Signature != ""
			},
			"valid_checksum": func(cfg *viracochan.Config) bool {
				return cfg.Validate() == nil
			},
			"recent_update": func(cfg *viracochan.Config) bool {
				return time.Since(cfg.Meta.Time) < 30*24*time.Hour
			},
			"version_continuity": func(cfg *viracochan.Config) bool {
				return cfg.Meta.Version > 0
			},
		},
	}
}

func (c *ComplianceChecker) Check(cfg *viracochan.Config) map[string]bool {
	results := make(map[string]bool)
	for name, rule := range c.rules {
		results[name] = rule(cfg)
	}
	return results
}

// nolint:gocyclo // complex logic is fine for demo
func main() {
	var (
		dataDir = flag.String("dir", "./audit-demo", "data directory")
		actors  = flag.Int("actors", 3, "number of actors to simulate")
	)
	flag.Parse()

	ctx := context.Background()

	// Clean up previous runs
	os.RemoveAll(*dataDir)

	fmt.Println("=== Audit Trail and Compliance Demo ===")
	fmt.Printf("Simulating %d actors with comprehensive audit logging\n\n", *actors)

	// Initialize storage and audit log
	storage, err := viracochan.NewFileStorage(*dataDir)
	if err != nil {
		log.Fatal("Failed to create storage:", err)
	}

	auditLog := NewAuditLog(storage)
	complianceChecker := NewComplianceChecker()

	// Create signers for different actors
	signers := make([]*viracochan.Signer, *actors)
	actorNames := make([]string, *actors)
	for i := 0; i < *actors; i++ {
		signer, err := viracochan.NewSigner()
		if err != nil {
			log.Fatal("Failed to create signer:", err)
		}
		signers[i] = signer
		actorNames[i] = fmt.Sprintf("actor-%d", i+1)
		fmt.Printf("Actor %d: %s (pubkey: %s)\n",
			i+1, actorNames[i], signer.PublicKey()[:12]+"...")
	}

	// Phase 1: Initial configuration by Actor 1
	fmt.Println("\n--- Phase 1: Initial Configuration ---")

	manager1, err := viracochan.NewManager(
		storage,
		viracochan.WithSigner(signers[0]),
		viracochan.WithJournalPath("actor-1.journal"),
	)
	if err != nil {
		log.Fatal("Failed to create manager:", err)
	}

	configID := "compliance-config"
	initialConfig := map[string]interface{}{
		"version": "1.0.0",
		"security": map[string]interface{}{
			"encryption":      "AES-256",
			"mfa_required":    true,
			"session_timeout": 3600,
		},
		"compliance": map[string]interface{}{
			"gdpr":  true,
			"hipaa": false,
			"sox":   true,
		},
		"created_by": actorNames[0],
		"created_at": time.Now().UTC().Format(time.RFC3339),
	}

	cfg, err := manager1.Create(ctx, configID, initialConfig)
	if err != nil {
		log.Fatal("Failed to create config:", err)
	}

	// Record audit event
	if err := auditLog.Record(AuditEvent{
		Timestamp:       time.Now(),
		Actor:           actorNames[0],
		Action:          "CREATE",
		ConfigID:        configID,
		Version:         cfg.Meta.Version,
		Checksum:        cfg.Meta.CS,
		Signature:       cfg.Meta.Signature,
		Verified:        true,
		ComplianceFlags: complianceChecker.Check(cfg),
	}); err != nil {
		log.Printf("Failed to record audit event: %v", err)
	}

	fmt.Printf("✓ %s created v%d (signed)\n", actorNames[0], cfg.Meta.Version)

	// Phase 2: Updates by different actors
	fmt.Println("\n--- Phase 2: Multi-Actor Updates ---")

	managers := []*viracochan.Manager{manager1}

	// Create managers for other actors
	for i := 1; i < *actors; i++ {
		m, err := viracochan.NewManager(
			storage,
			viracochan.WithSigner(signers[i]),
			viracochan.WithJournalPath(fmt.Sprintf("actor-%d.journal", i+1)),
		)
		if err != nil {
			log.Fatal("Failed to create manager:", err)
		}
		managers = append(managers, m)
	}

	// Simulate various updates
	updates := []struct {
		actor       int
		changes     map[string]interface{}
		description string
	}{
		{
			actor: 1,
			changes: map[string]interface{}{
				"compliance": map[string]interface{}{
					"gdpr":  true,
					"hipaa": true,
					"sox":   true,
				},
			},
			description: "Enable HIPAA compliance",
		},
		{
			actor: 0,
			changes: map[string]interface{}{
				"security": map[string]interface{}{
					"encryption":      "AES-256",
					"mfa_required":    true,
					"session_timeout": 1800,
					"ip_whitelist":    []string{"10.0.0.0/8", "192.168.0.0/16"},
				},
			},
			description: "Add IP whitelist and reduce session timeout",
		},
		{
			actor: 2,
			changes: map[string]interface{}{
				"monitoring": map[string]interface{}{
					"enabled":        true,
					"level":          "verbose",
					"retention_days": 90,
				},
			},
			description: "Enable monitoring",
		},
		{
			actor: 0,
			changes: map[string]interface{}{
				"version": "2.0.0",
				"features": map[string]interface{}{
					"api_v2":   true,
					"webhooks": true,
					"sso":      false,
				},
			},
			description: "Major version update with new features",
		},
		{
			actor: 1,
			changes: map[string]interface{}{
				"security": map[string]interface{}{
					"encryption":      "AES-256-GCM",
					"mfa_required":    true,
					"session_timeout": 1800,
					"password_policy": map[string]interface{}{
						"min_length":      12,
						"require_special": true,
						"require_numbers": true,
					},
				},
			},
			description: "Strengthen password policy",
		},
	}

	for _, update := range updates {
		if update.actor >= len(managers) {
			continue
		}

		// Get current config
		current, err := managers[update.actor].GetLatest(ctx, configID)
		if err != nil {
			fmt.Printf("✗ %s failed to get latest: %v\n", actorNames[update.actor], err)
			continue
		}

		// Merge changes
		var content map[string]interface{}
		if err := json.Unmarshal(current.Content, &content); err != nil {
			log.Printf("Failed to unmarshal content: %v", err)
		}
		for k, v := range update.changes {
			content[k] = v
		}
		content["last_modified_by"] = actorNames[update.actor]
		content["last_modified_at"] = time.Now().UTC().Format(time.RFC3339)

		// Update configuration
		newCfg, err := managers[update.actor].Update(ctx, configID, content)
		if err != nil {
			fmt.Printf("✗ %s failed to update: %v\n", actorNames[update.actor], err)
			continue
		}

		// Verify previous actor's signature
		verified := false
		for i, signer := range signers {
			if err := managers[update.actor].Verify(current, signer.PublicKey()); err == nil {
				verified = true
				fmt.Printf("✓ %s: %s (v%d, verified sig from %s)\n",
					actorNames[update.actor],
					update.description,
					newCfg.Meta.Version,
					actorNames[i])
				break
			}
		}

		if !verified {
			fmt.Printf("⚠ %s: %s (v%d, signature not verified)\n",
				actorNames[update.actor],
				update.description,
				newCfg.Meta.Version)
		}

		// Record audit event
		if err := auditLog.Record(AuditEvent{
			Timestamp:       time.Now(),
			Actor:           actorNames[update.actor],
			Action:          "UPDATE",
			ConfigID:        configID,
			Version:         newCfg.Meta.Version,
			Checksum:        newCfg.Meta.CS,
			Changes:         update.changes,
			Signature:       newCfg.Meta.Signature,
			Verified:        verified,
			ComplianceFlags: complianceChecker.Check(newCfg),
		}); err != nil {
			log.Printf("Failed to record audit event: %v", err)
		}

		time.Sleep(100 * time.Millisecond) // Ensure different timestamps
	}

	// Phase 3: Rollback operation
	fmt.Println("\n--- Phase 3: Rollback Operation ---")

	// Actor 0 performs rollback
	rollbackVersion := uint64(3)
	fmt.Printf("%s initiating rollback to v%d...\n", actorNames[0], rollbackVersion)

	rolledBack, err := managers[0].Rollback(ctx, configID, rollbackVersion)
	if err != nil {
		fmt.Printf("✗ Rollback failed: %v\n", err)
	} else {
		fmt.Printf("✓ Rolled back to v%d content, created new v%d\n",
			rollbackVersion, rolledBack.Meta.Version)

		// Record rollback audit event
		if err := auditLog.Record(AuditEvent{
			Timestamp:       time.Now(),
			Actor:           actorNames[0],
			Action:          fmt.Sprintf("ROLLBACK_TO_V%d", rollbackVersion),
			ConfigID:        configID,
			Version:         rolledBack.Meta.Version,
			Checksum:        rolledBack.Meta.CS,
			Signature:       rolledBack.Meta.Signature,
			Verified:        true,
			ComplianceFlags: complianceChecker.Check(rolledBack),
		}); err != nil {
			log.Printf("Failed to record audit event: %v", err)
		}
	}

	// Phase 4: Chain verification
	fmt.Println("\n--- Phase 4: Complete Chain Verification ---")

	history, err := managers[0].GetHistory(ctx, configID)
	if err != nil {
		log.Fatal("Failed to get history:", err)
	}

	fmt.Printf("Found %d versions in history\n", len(history))

	// Verify entire chain
	fmt.Println("\nVerifying chain integrity:")
	for i, cfg := range history {
		// Check basic validation
		if err := cfg.Validate(); err != nil {
			fmt.Printf("  ✗ v%d: invalid checksum\n", cfg.Meta.Version)
			continue
		}

		// Check chain continuity
		if i > 0 {
			if err := cfg.NextOf(history[i-1]); err != nil {
				fmt.Printf("  ✗ v%d: chain break - %v\n", cfg.Meta.Version, err)
				continue
			}
		}

		// Verify signature
		signatureValid := false
		var signerName string
		for j, signer := range signers {
			if err := managers[0].Verify(cfg, signer.PublicKey()); err == nil {
				signatureValid = true
				signerName = actorNames[j]
				break
			}
		}

		if signatureValid {
			fmt.Printf("  ✓ v%d: valid (signed by %s)\n", cfg.Meta.Version, signerName)
		} else {
			fmt.Printf("  ⚠ v%d: valid but signature not recognized\n", cfg.Meta.Version)
		}

		// Record verification audit
		if err := auditLog.Record(AuditEvent{
			Timestamp:       time.Now(),
			Actor:           "SYSTEM",
			Action:          "VERIFY",
			ConfigID:        configID,
			Version:         cfg.Meta.Version,
			Checksum:        cfg.Meta.CS,
			Signature:       cfg.Meta.Signature,
			Verified:        signatureValid,
			ComplianceFlags: complianceChecker.Check(cfg),
		}); err != nil {
			log.Printf("Failed to record audit event: %v", err)
		}
	}

	// Phase 5: Compliance Report
	fmt.Println("\n--- Phase 5: Compliance Analysis ---")

	// Analyze compliance across versions
	complianceStats := make(map[string]int)
	for _, event := range auditLog.Events {
		for rule, passed := range event.ComplianceFlags {
			if passed {
				complianceStats[rule]++
			}
		}
	}

	fmt.Println("\nCompliance Rule Statistics:")
	rules := []string{}
	for rule := range complianceStats {
		rules = append(rules, rule)
	}
	sort.Strings(rules)

	for _, rule := range rules {
		percentage := float64(complianceStats[rule]) / float64(len(auditLog.Events)) * 100
		fmt.Printf("  %s: %d/%d (%.1f%%)\n",
			rule, complianceStats[rule], len(auditLog.Events), percentage)
	}

	// Phase 6: Forensic Analysis
	fmt.Println("\n--- Phase 6: Forensic Analysis ---")

	// Detect suspicious patterns
	fmt.Println("\nActivity Timeline:")

	// Group events by time window
	timeWindows := make(map[string][]AuditEvent)
	for _, event := range auditLog.Events {
		window := event.Timestamp.Format("15:04")
		timeWindows[window] = append(timeWindows[window], event)
	}

	for window, events := range timeWindows {
		if len(events) > 2 {
			fmt.Printf("  ⚠ High activity at %s: %d events\n", window, len(events))
		}
	}

	// Check for rapid successive updates
	for i := 1; i < len(auditLog.Events); i++ {
		timeDiff := auditLog.Events[i].Timestamp.Sub(auditLog.Events[i-1].Timestamp)
		if timeDiff < 1*time.Second && auditLog.Events[i].Action == "UPDATE" {
			fmt.Printf("  ⚠ Rapid update detected: v%d to v%d in %v\n",
				auditLog.Events[i-1].Version,
				auditLog.Events[i].Version,
				timeDiff)
		}
	}

	// Phase 7: Export Audit Report
	fmt.Println("\n--- Phase 7: Audit Report Generation ---")

	report := auditLog.GenerateReport()
	fmt.Println(report)

	// Save detailed audit log
	auditData, err := json.MarshalIndent(auditLog.Events, "", "  ")
	if err != nil {
		log.Fatal("Failed to marshal audit log:", err)
	}

	auditFile := filepath.Join(*dataDir, "complete-audit.json")
	if err := os.WriteFile(auditFile, auditData, 0o600); err != nil {
		log.Fatal("Failed to save audit log:", err)
	}

	fmt.Printf("\n✓ Complete audit log saved to %s (%d bytes)\n", auditFile, len(auditData))

	// Generate compliance certificate
	fmt.Println("\n=== Compliance Certificate ===")
	fmt.Printf("Organization: Demo Corp\n")
	fmt.Printf("Audit Period: %s\n", time.Now().Format("2006-01-02"))
	fmt.Printf("Total Configurations Audited: %d\n", len(history))
	fmt.Printf("Total Audit Events: %d\n", len(auditLog.Events))

	compliantCount := 0
	for _, event := range auditLog.Events {
		if event.Verified && allCompliant(event.ComplianceFlags) {
			compliantCount++
		}
	}
	complianceRate := float64(compliantCount) / float64(len(auditLog.Events)) * 100

	fmt.Printf("Compliance Rate: %.1f%%\n", complianceRate)
	switch {
	case complianceRate >= 90:
		fmt.Println("Status: ✓ COMPLIANT")
	case complianceRate >= 70:
		fmt.Println("Status: ⚠ PARTIALLY COMPLIANT")
	default:
		fmt.Println("Status: ✗ NON-COMPLIANT")
	}

	fmt.Println("\n✓ Audit trail and compliance demo completed")
}
