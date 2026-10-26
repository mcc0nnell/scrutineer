package worker

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"scrutineer/internal/coverage"
	"scrutineer/internal/db"
)

type preflightMutationRunner struct {
	calls  int
	mutate func(SkillJob) error
}

func (r *preflightMutationRunner) RunSkill(ctx context.Context, sj SkillJob, emit func(Event)) (SkillResult, error) {
	if err := sj.checkCapabilities(ctx, nil, false, emit); err != nil {
		return SkillResult{}, err
	}
	r.calls++
	if r.calls == 1 {
		if err := r.mutate(sj); err != nil {
			return SkillResult{}, err
		}
		return SkillResult{Report: "could not resolve dependencies"}, nil
	}
	return SkillResult{Report: `{}`, SessionID: "repair-session"}, nil
}

func (*preflightMutationRunner) SkillDir(workRoot, name string) string {
	return ClaudeHarness{}.SkillDir(workRoot, name)
}

func mutatePreflightFiles(sj SkillJob, mode, target string) error {
	for _, dir := range []string{sj.WorkRoot, sj.SkillDir} {
		path := filepath.Join(dir, "context.json")
		if err := os.Remove(path); err != nil {
			return err
		}
		var err error
		switch mode {
		case "symlink":
			err = os.Symlink(target, path)
		case "hardlink":
			err = os.Link(target, path)
		case "malformed":
			err = os.WriteFile(path, []byte("not JSON"), 0o600)
		case "deleted":
		default:
			return fmt.Errorf("unknown mutation %q", mode)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func TestCapabilityPreflightOnceAcrossFallbackAndRepair(t *testing.T) {
	for _, mode := range []string{"symlink", "hardlink", "deleted", "malformed"} {
		t.Run(mode, func(t *testing.T) { testPreflightFallbackAndRepair(t, mode) })
	}
}

func testPreflightFallbackAndRepair(t *testing.T, mode string) {
	t.Helper()
	w, repo := newStreamWorker(t)
	scan := db.Scan{RepositoryID: repo.ID, Repository: repo, Kind: JobSkill, Status: db.ScanRunning, SubPath: "activesupport"}
	if err := w.DB.Create(&scan).Error; err != nil {
		t.Fatal(err)
	}
	skill := db.Skill{Name: "audit", RequiresCommands: "missing-preflight-command", DegradedMode: true, SchemaJSON: `{"type":"object"}`}
	work := t.TempDir()
	sj := SkillJob{WorkRoot: work, SkillDir: ClaudeHarness{}.SkillDir(work, skill.Name)}
	document, err := w.stageWorkspace(t.Context(), work, sj.SkillDir, &scan, &skill)
	if err != nil {
		t.Fatal(err)
	}
	w.configureCapabilityPreflight(t.Context(), &scan, &skill, &sj, document)
	target := filepath.Join(t.TempDir(), "host-file")
	const original = "host-owned data"
	if err := os.WriteFile(target, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	runner := &preflightMutationRunner{mutate: func(job SkillJob) error { return mutatePreflightFiles(job, mode, target) }}
	w.Runner = runner
	w.PrepareRepoSrc = stubWholeTreePrep
	probes := 0
	emit := func(e Event) {
		if strings.HasPrefix(e.Text, "capability preflight ") {
			probes++
		}
	}
	if _, err := w.runSkillWithFallback(t.Context(), &scan, &skill, sj, work, true, emit); err != nil {
		t.Fatal(err)
	}
	scan.SessionID = "repair-session"
	if _, ok, err := w.repairSchemaReport(t.Context(), &skill, &scan, sj, "invalid", "invalid JSON", emit); err != nil || !ok {
		t.Fatal("schema repair failed after context mutation")
	}
	if runner.calls != 3 || probes != 1 || scan.ScopeMode != "soft" {
		t.Fatalf("calls=%d probes=%d scope=%s", runner.calls, probes, scan.ScopeMode)
	}
	if scan.Completeness != coverage.CompletenessPartial {
		t.Fatal("fallback or repair erased degraded coverage")
	}
	if got, err := os.ReadFile(target); err != nil || string(got) != original {
		t.Fatalf("host file changed: %q err=%v", got, err)
	}
	// A newly configured attempt must not reuse the previous attempt's cache.
	w.configureCapabilityPreflight(t.Context(), &scan, &skill, &sj, document)
	if err := sj.checkCapabilities(t.Context(), nil, false, emit); err != nil || probes != 2 {
		t.Fatalf("new attempt did not probe: probes=%d err=%v", probes, err)
	}
	if got, err := os.ReadFile(target); err != nil || string(got) != original {
		t.Fatalf("fresh preflight followed a link: %q err=%v", got, err)
	}
}

func TestCapabilityPreflightCachesFailure(t *testing.T) {
	sentinel := errors.New("cannot persist")
	calls := 0
	sj := SkillJob{WorkRoot: t.TempDir(), RequiresCommands: []string{"sh"}, preflight: &capabilityPreflightState{},
		RecordPreflight: func(coverage.Preflight) error { calls++; return sentinel },
	}
	for range 2 {
		job := sj
		if err := job.checkCapabilities(t.Context(), nil, false, func(Event) {}); !errors.Is(err, sentinel) {
			t.Fatalf("lost cached failure: %v", err)
		}
	}
	if calls != 1 {
		t.Fatalf("recorded %d times, want once", calls)
	}
}

func TestWriteSkillContextRefusesParentEscape(t *testing.T) {
	work, outside := t.TempDir(), t.TempDir()
	target := filepath.Join(outside, "context.json")
	if err := os.WriteFile(target, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	skillDir := filepath.Join(work, "skill")
	if err := os.Symlink(outside, skillDir); err != nil {
		t.Fatal(err)
	}
	if err := writeSkillContext(work, skillDir, skillContext{}); err == nil {
		t.Fatal("accepted an escaping parent symlink")
	}
	if data, err := os.ReadFile(target); err != nil || string(data) != "keep" {
		t.Fatalf("external context changed: %q err=%v", data, err)
	}
}

func TestCapabilityProbeArgsExcludeAgentCredentials(t *testing.T) {
	d := ContainerRunner{Hardened: true, Harness: stubHarness{
		env:   []string{"ANTHROPIC_API_KEY", "OPENAI_API_KEY", "MODEL_BASE_URL=https://model.example"},
		state: []string{"AGENT_STATE=/harness-state"},
	}}
	hnet := hardenedNet{name: "isolated", gatewayIP: "192.0.2.1"}
	base := d.buildContainerBaseArgs("/workspace", hnet, "/work")
	agent := d.buildRunArgsForProvider("/workspace", "image", hnet, "/agent-state", opencodeProvider{Env: map[string]string{"PROVIDER_TOKEN": "secret"}}, "/work")
	if !slices.Equal(agent[:len(base)], base) {
		t.Fatal("probe and agent do not share runtime isolation flags")
	}
	for _, field := range []string{"ANTHROPIC_API_KEY", "OPENAI_API_KEY", "MODEL_BASE_URL", "PROVIDER_TOKEN", "/harness-state", "/agent-state"} {
		if strings.Contains(strings.Join(base, " "), field) || !strings.Contains(strings.Join(agent, " "), field) {
			t.Errorf("credential/state %q must only appear in agent args", field)
		}
	}
	for _, pair := range [][2]string{{"-v", "/workspace:/work"}, {"-w", "/work"}, {"--network", "isolated"}} {
		if !hasAdjacent(base, pair[0], pair[1]) {
			t.Errorf("probe missing isolation flag %v", pair)
		}
	}
}
