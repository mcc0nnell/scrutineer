package web

// Rizzer witness attachment is an operator-only, reviewed import into the
// existing persistent FindingPoC store, never a scan-token or disclosure route.
import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"

	"scrutineer/internal/db"
	"scrutineer/internal/poc"
)

const rizzerWitnessMaxBytes = 1 << 20 // Existing FindingPoC per-file limit.
const rizzerWitnessPath = "rizzer/candidate-evidence.zip"

var rizzerHex = regexp.MustCompile(`^[a-f0-9]{64}$`)
var rizzerCommit = regexp.MustCompile(`^[a-f0-9]{40,64}$`)
var rizzerCase = regexp.MustCompile(`^findings/case-[0-9]+\.(bin|log)$`)
var rizzerHarness = regexp.MustCompile(`^harness\.(c|cc|cpp|cxx)$`)

type rizzerManifest struct {
	Protocol                 string            `json:"protocol"`
	SourceCommit             string            `json:"sourceCommit"`
	SourcePath               string            `json:"sourcePath"`
	CampaignEvidenceSHA      string            `json:"campaignEvidenceSha256"`
	ReviewSHA                string            `json:"reviewSha256"`
	Included                 map[string]string `json:"includedSha256"`
	Execution                string            `json:"execution"`
	SecurityFindingConfirmed bool              `json:"securityFindingConfirmed"`
}
type rizzerReview struct {
	Protocol                 string `json:"protocol"`
	Commit                   string `json:"commit"`
	Source                   string `json:"source"`
	CampaignEvidenceSHA      string `json:"campaignEvidenceSha256"`
	SourceSHA                string `json:"sourceSha256"`
	CampaignStatus           string `json:"campaignStatus"`
	HumanReview              string `json:"humanReview"`
	RuntimeReplay            string `json:"runtimeReplay"`
	SecurityFindingConfirmed bool   `json:"securityFindingConfirmed"`
	Candidates               []struct {
		Input         string `json:"input"`
		InputSHA      string `json:"inputSha256"`
		Diagnostic    string `json:"diagnostic"`
		DiagnosticSHA string `json:"diagnosticSha256"`
	} `json:"candidates"`
}
type rizzerEvidence struct {
	Schema    string            `json:"schema"`
	Engine    string            `json:"engine"`
	Admission string            `json:"admission"`
	Status    string            `json:"status"`
	SourceSHA string            `json:"source_sha256"`
	EngineSHA string            `json:"engine_sha256"`
	Files     map[string]string `json:"files"`
	Summary   struct {
		Findings int `json:"findings"`
	} `json:"summary"`
}

func rizzerDigest(content []byte) string {
	h := sha256.Sum256(content)
	return hex.EncodeToString(h[:])
}

func validRizzerZipName(name string) bool {
	if name == "evidence.json" || name == "review.json" ||
		name == "witness-manifest.json" || name == "engine.cc" || name == "summary.json" {
		return true
	}
	return rizzerHarness.MatchString(name) || rizzerCase.MatchString(name)
}

// checkRizzerWitness validates untrusted archive bytes in memory without
// extraction or execution. SHA-256 consistency is not producer authentication.
func checkRizzerWitness(raw []byte, finding db.Finding) (string, error) {
	if len(raw) == 0 || len(raw) > rizzerWitnessMaxBytes {
		return "", errors.New("witness must be 1..1048576 bytes")
	}
	if finding.ImportedFrom != "Rizzer (unverified candidates)" {
		return "", errors.New("witness can only attach to imported Rizzer candidates")
	}
	archive, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		return "", fmt.Errorf("invalid ZIP: %w", err)
	}
	if len(archive.File) < 7 || len(archive.File) > 136 {
		return "", errors.New("invalid witness ZIP member count")
	}
	files := make(map[string][]byte, len(archive.File))
	total := int64(0)
	for _, entry := range archive.File {
		if !validRizzerZipName(entry.Name) || entry.FileInfo().Mode().IsRegular() == false ||
			entry.FileInfo().IsDir() || entry.Method != zip.Store || entry.Flags&1 != 0 ||
			entry.UncompressedSize64 > rizzerWitnessMaxBytes {
			return "", errors.New("unsafe witness ZIP entry")
		}
		if _, exists := files[entry.Name]; exists {
			return "", errors.New("duplicate witness ZIP entry")
		}
		total += int64(entry.UncompressedSize64)
		if total > rizzerWitnessMaxBytes {
			return "", errors.New("witness expanded size exceeded")
		}
		reader, err := entry.Open()
		if err != nil {
			return "", fmt.Errorf("open ZIP entry: %w", err)
		}
		data, readErr := io.ReadAll(io.LimitReader(reader, int64(rizzerWitnessMaxBytes)+1))
		closeErr := reader.Close()
		if readErr != nil || closeErr != nil || uint64(len(data)) != entry.UncompressedSize64 {
			return "", errors.New("invalid ZIP entry length or checksum")
		}
		files[entry.Name] = data
	}
	for _, name := range []string{"evidence.json", "review.json", "witness-manifest.json", "engine.cc", "summary.json"} {
		if _, ok := files[name]; !ok {
			return "", errors.New("missing witness file: " + name)
		}
	}
	var manifest rizzerManifest
	var review rizzerReview
	var evidence rizzerEvidence
	var summary struct {
		Findings int `json:"findings"`
	}
	if json.Unmarshal(files["witness-manifest.json"], &manifest) != nil ||
		json.Unmarshal(files["review.json"], &review) != nil ||
		json.Unmarshal(files["evidence.json"], &evidence) != nil ||
		json.Unmarshal(files["summary.json"], &summary) != nil {
		return "", errors.New("invalid witness manifest JSON")
	}
	if manifest.Protocol != "rizzer.scrutineer-evidence-pack/v1" ||
		review.Protocol != "rizzer.scrutineer-review/v1" ||
		evidence.Schema != "ihb.native-fuzz-evidence.v0" || evidence.Engine != "ihb-native-v0" ||
		evidence.Admission != "not_performed" ||
		manifest.Execution != "none" || manifest.SecurityFindingConfirmed ||
		review.SecurityFindingConfirmed || review.HumanReview != "required" ||
		review.RuntimeReplay != "not_performed" ||
		!rizzerHex.MatchString(manifest.CampaignEvidenceSHA) ||
		!rizzerCommit.MatchString(manifest.SourceCommit) {
		return "", errors.New("invalid witness protocol or verification claims")
	}
	if manifest.SourceCommit != finding.Commit || manifest.SourcePath != finding.Location ||
		review.Commit != manifest.SourceCommit || review.Source != manifest.SourcePath ||
		review.CampaignEvidenceSHA != manifest.CampaignEvidenceSHA ||
		evidence.Status != review.CampaignStatus ||
		!strings.Contains(finding.Trace, "Campaign evidence SHA-256: "+manifest.CampaignEvidenceSHA+".") {
		return "", errors.New("witness does not match the imported Rizzer finding")
	}
	if review.CampaignStatus != "asan_failure" && review.CampaignStatus != "ubsan_failure" {
		return "", errors.New("witness is not a sanitizer campaign")
	}
	if len(manifest.Included) != len(files)-1 || len(evidence.Files) == 0 {
		return "", errors.New("witness file manifest inventory mismatch")
	}
	for path, data := range files {
		if path == "witness-manifest.json" {
			continue
		}
		if !rizzerHex.MatchString(manifest.Included[path]) ||
			rizzerDigest(data) != manifest.Included[path] {
			return "", errors.New("witness member digest mismatch: " + path)
		}
		if path != "evidence.json" && path != "review.json" &&
			evidence.Files[path] != manifest.Included[path] {
			return "", errors.New("witness member differs from original campaign: " + path)
		}
	}
	if manifest.ReviewSHA != rizzerDigest(files["review.json"]) ||
		manifest.CampaignEvidenceSHA != rizzerDigest(files["evidence.json"]) ||
		evidence.Files["engine.cc"] != evidence.EngineSHA ||
		summary.Findings != evidence.Summary.Findings ||
		summary.Findings != len(review.Candidates) ||
		summary.Findings < 1 || summary.Findings > 64 {
		return "", errors.New("witness evidence or summary mismatch")
	}
	harnessCount := 0
	for path := range files {
		if rizzerHarness.MatchString(path) {
			harnessCount++
			if evidence.SourceSHA != manifest.Included[path] || review.SourceSHA != evidence.SourceSHA {
				return "", errors.New("witness harness source digest mismatch")
			}
		}
	}
	if harnessCount != 1 {
		return "", errors.New("expected exactly one native harness")
	}
	used := make(map[string]bool)
	for _, candidate := range review.Candidates {
		if !rizzerCase.MatchString(candidate.Input) ||
			!strings.HasSuffix(candidate.Input, ".bin") ||
			candidate.Diagnostic != strings.TrimSuffix(candidate.Input, ".bin")+".log" ||
			used[candidate.Input] || !rizzerHex.MatchString(candidate.InputSHA) ||
			candidate.InputSHA != manifest.Included[candidate.Input] ||
			candidate.DiagnosticSHA != manifest.Included[candidate.Diagnostic] {
			return "", errors.New("mismatched witness candidate input or diagnostic")
		}
		used[candidate.Input] = true
	}
	if len(files) != 6+len(review.Candidates)*2 { // 5 root files + harness + paired candidates
		return "", errors.New("unexpected witness file count")
	}
	return rizzerDigest(raw), nil
}

func (s *Server) apiAttachRizzerWitness(w http.ResponseWriter, r *http.Request) {
	finding, ok := s.loadExportFindingByID(w, r)
	if !ok {
		return
	}
	if r.Header.Get("X-Rizzer-Candidate-Reviewed") != "true" {
		writeAPIError(w, http.StatusBadRequest, "explicit X-Rizzer-Candidate-Reviewed: true required")
		return
	}
	if r.Header.Get("Content-Type") != "application/zip" {
		writeAPIError(w, http.StatusUnsupportedMediaType, "application/zip required")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, rizzerWitnessMaxBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeAPIError(w, http.StatusRequestEntityTooLarge, "witness exceeds persistent PoC size limit")
		return
	}
	digest, err := checkRizzerWitness(body, finding)
	if err != nil {
		writeAPIError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	file := poc.File{Path: rizzerWitnessPath, Data: body, SHA256: digest}
	if err := poc.ValidateFiles([]poc.File{file}); err != nil {
		writeAPIError(w, http.StatusUnprocessableEntity, "witness cannot fit persistent PoC storage")
		return
	}
	encoded, err := json.Marshal([]poc.File{file})
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "encode witness")
		return
	}
	prior, err := db.LoadFindingPoC(s.DB, finding.ID)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "read existing evidence")
		return
	}
	if prior != nil {
		saved, decodeErr := poc.Decode(prior.Files)
		if decodeErr == nil && len(saved) == 1 &&
			saved[0].Path == rizzerWitnessPath && saved[0].SHA256 == digest &&
			prior.Commit == finding.Commit {
			writeJSON(w, http.StatusOK, map[string]any{"status": "existing", "sha256": digest, "finding_id": finding.ID})
			return
		}
		writeAPIError(w, http.StatusConflict, "finding already has persistent PoC material")
		return
	}
	row := db.FindingPoC{FindingID: finding.ID, ScanID: finding.ScanID, Commit: finding.Commit, Files: encoded}
	if err := s.DB.Create(&row).Error; err != nil {
		writeAPIError(w, http.StatusConflict, "could not attach immutable evidence; check for concurrent capture")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"status": "attached", "finding_id": finding.ID, "sha256": digest,
		"download":               fmt.Sprintf("/api/v1/findings/%d/rizzer-witness", finding.ID),
		"verified_vulnerability": false,
	})
}

func (s *Server) apiDownloadRizzerWitness(w http.ResponseWriter, r *http.Request) {
	finding, ok := s.loadExportFindingByID(w, r)
	if !ok {
		return
	}
	row, err := db.LoadFindingPoC(s.DB, finding.ID)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "load witness")
		return
	}
	if row == nil {
		writeAPIError(w, http.StatusNotFound, "no witness attached")
		return
	}
	files, err := poc.Decode(row.Files)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "stored evidence corrupt")
		return
	}
	if len(files) != 1 || files[0].Path != rizzerWitnessPath {
		writeAPIError(w, http.StatusNotFound, "no Rizzer witness attached")
		return
	}
	if _, err := checkRizzerWitness(files[0].Data, finding); err != nil {
		writeAPIError(w, http.StatusInternalServerError, "stored witness integrity mismatch")
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="candidate-evidence.zip"`)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(files[0].Data)
}

func (s *Server) hasRizzerWitness(f db.Finding) bool {
	if f.ImportedFrom != "Rizzer (unverified candidates)" {
		return false
	}
	row, err := db.LoadFindingPoC(s.DB, f.ID)
	if err != nil || row == nil {
		return false
	}
	files, err := poc.Decode(row.Files)
	if err != nil || len(files) != 1 || files[0].Path != rizzerWitnessPath {
		return false
	}
	_, err = checkRizzerWitness(files[0].Data, f)
	return err == nil
}
