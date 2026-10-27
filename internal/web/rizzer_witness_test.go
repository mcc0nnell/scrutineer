package web

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"scrutineer/internal/db"
)

const testRizzerCommit = "0123456789abcdef0123456789abcdef01234567"
const testRizzerRepository = "https://github.com/example/rizzer"

func sampleRizzerFiles(t *testing.T) ([]byte, []byte) {
	t.Helper()
	inputs := map[string][]byte{
		"harness.c":           []byte("int IHBTestOneInput(void){return 0;}\n"),
		"engine.cc":           []byte("int main(){return 0;}\n"),
		"summary.json":        []byte(`{"findings":1}`),
		"findings/case-0.bin": {0, 255, 10},
		"findings/case-0.log": []byte("==1==ERROR: AddressSanitizer: heap-buffer-overflow\n"),
	}
	originalDigests := map[string]string{}
	for k, v := range inputs {
		originalDigests[k] = rizzerDigest(v)
	}
	evidence := map[string]any{
		"schema": "ihb.native-fuzz-evidence.v0", "engine": "ihb-native-v0",
		"admission": "not_performed", "status": "asan_failure",
		"source_sha256": originalDigests["harness.c"],
		"engine_sha256": originalDigests["engine.cc"],
		"files":         originalDigests, "summary": map[string]any{"findings": 1},
	}
	e, _ := json.Marshal(evidence)
	review := map[string]any{
		"protocol": "rizzer.scrutineer-review/v1", "commit": testRizzerCommit,
		"source": "fixtures/buggy.c", "sourceSha256": originalDigests["harness.c"],
		"campaignEvidenceSha256": rizzerDigest(e), "campaignStatus": "asan_failure",
		"humanReview": "required", "runtimeReplay": "not_performed",
		"securityFindingConfirmed": false,
		"candidates": []any{map[string]any{
			"input": "findings/case-0.bin", "inputSha256": originalDigests["findings/case-0.bin"],
			"diagnostic": "findings/case-0.log", "diagnosticSha256": originalDigests["findings/case-0.log"],
		}},
	}
	r, _ := json.Marshal(review)
	members := map[string][]byte{"evidence.json": e, "review.json": r}
	for k, v := range inputs {
		members[k] = v
	}
	digests := map[string]string{}
	for k, v := range members {
		digests[k] = rizzerDigest(v)
	}
	manifest := map[string]any{
		"protocol":     "rizzer.scrutineer-evidence-pack/v1",
		"sourceCommit": testRizzerCommit, "sourcePath": "fixtures/buggy.c",
		"campaignEvidenceSha256": rizzerDigest(e), "reviewSha256": rizzerDigest(r),
		"includedSha256": digests, "execution": "none", "securityFindingConfirmed": false,
	}
	m, _ := json.Marshal(manifest)
	members["witness-manifest.json"] = m
	var output bytes.Buffer
	writer := zip.NewWriter(&output)
	for _, name := range []string{
		"evidence.json", "review.json", "summary.json", "engine.cc", "harness.c",
		"findings/case-0.bin", "findings/case-0.log", "witness-manifest.json",
	} {
		hdr := &zip.FileHeader{Name: name, Method: zip.Store}
		hdr.SetMode(0600)
		handle, err := writer.CreateHeader(hdr)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = handle.Write(members[name]); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	report := fmt.Sprintf(`{"version":"2.1.0","runs":[{
  "tool":{"driver":{"name":"Rizzer (unverified candidates)","rules":[{
    "id":"rizzer/native-sanitizer-candidate",
    "shortDescription":{"text":"Unverified native sanitizer observation"},
    "properties":{"precision":"low"}
  }]}},
  "versionControlProvenance":[{"repositoryUri":%q,"revisionId":%q}],
  "results":[{"ruleId":"rizzer/native-sanitizer-candidate","level":"note",
    "message":{"text":%q},
    "locations":[{"physicalLocation":{"artifactLocation":{"uri":"fixtures/buggy.c"}}}]
  }]
 }]}`, testRizzerRepository, testRizzerCommit,
		"Unverified Rizzer asan/heap-buffer-overflow. Campaign evidence SHA-256: "+rizzerDigest(e)+". Reachability and severity unproven.")
	return []byte(report), output.Bytes()
}

func importedRizzerFinding(t *testing.T, s *Server, report []byte) db.Finding {
	t.Helper()
	w := postImport(t, s, "/api/v1/import?revalidate=false", string(report))
	if w.Code != http.StatusCreated {
		t.Fatalf("SARIF import status=%d: %s", w.Code, w.Body.String())
	}
	var row db.Finding
	if err := s.DB.First(&row).Error; err != nil {
		t.Fatal(err)
	}
	if row.ImportedFrom != "Rizzer (unverified candidates)" || row.Commit != testRizzerCommit {
		t.Fatalf("incorrect imported identity: %+v", row)
	}
	return row
}

func witnessReq(t *testing.T, s *Server, method string, id uint, data []byte, ack bool) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, fmt.Sprintf("/api/v1/findings/%d/rizzer-witness", id), bytes.NewReader(data))
	asOperator(r)
	if method == "POST" {
		r.Header.Set("Content-Type", "application/zip")
		if ack {
			r.Header.Set("X-Rizzer-Candidate-Reviewed", "true")
		}
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}

func TestRizzerWitnessAttachAndDownload(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	sarif, archive := sampleRizzerFiles(t)
	finding := importedRizzerFinding(t, s, sarif)

	if response := witnessReq(t, s, "POST", finding.ID, archive, false); response.Code != 400 {
		t.Fatalf("no review acknowledgement: %d", response.Code)
	}
	response := witnessReq(t, s, "POST", finding.ID, archive, true)
	if response.Code != 201 {
		t.Fatalf("attach status=%d: %s", response.Code, response.Body.String())
	}
	if response := witnessReq(t, s, "POST", finding.ID, archive, true); response.Code != 200 {
		t.Fatalf("idempotent attach status=%d: %s", response.Code, response.Body.String())
	}
	got := witnessReq(t, s, "GET", finding.ID, nil, false)
	if got.Code != 200 || !bytes.Equal(got.Body.Bytes(), archive) ||
		!strings.Contains(got.Header().Get("Content-Disposition"), "attachment") ||
		got.Header().Get("Content-Type") != "application/octet-stream" {
		t.Fatalf("download status=%d bytes=%d headers=%v", got.Code, got.Body.Len(), got.Header())
	}
	row, err := db.LoadFindingPoC(s.DB, finding.ID)
	if err != nil || row == nil {
		t.Fatalf("persistent PoC: %v", err)
	}
	// The finding page offers a direct operator-only witness download link.
	page := httptest.NewRecorder()
	pageReq := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/findings/%d", finding.ID), nil)
	asOperator(pageReq)
	s.Handler().ServeHTTP(page, pageReq)
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(),
		fmt.Sprintf("/api/v1/findings/%d/rizzer-witness", finding.ID)) {
		t.Fatalf("finding page missing witness download: status=%d", page.Code)
	}
	// Existing finding bundle includes the *exact* bytes, not reconstructed prose.
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/findings/%d/bundle.tar.gz", finding.ID), nil)
	asOperator(r)
	s.Handler().ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("finding evidence bundle: %d %s", w.Code, w.Body.String())
	}
	files := readArchive(t, w.Body.Bytes())
	if !bytes.Equal(files["poc/"+rizzerWitnessPath], archive) {
		t.Fatal("finding bundle did not preserve witness bytes")
	}
	// Operator-only, even if the caller supplies a scan token or knows the ID.
	unauth := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/findings/%d/rizzer-witness", finding.ID), nil)
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, unauth)
	if w.Code == http.StatusOK {
		t.Fatal("unauthenticated witness disclosed")
	}
}

func TestRizzerWitnessRejectsCorruptionAndForeignFindings(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	sarif, archive := sampleRizzerFiles(t)
	f := importedRizzerFinding(t, s, sarif)
	bad := append([]byte(nil), archive...)
	// Truncation or ZIP CRC failure must not create stored PoC.
	bad[len(bad)/2] ^= 255
	if w := witnessReq(t, s, "POST", f.ID, bad, true); w.Code != 422 {
		t.Fatalf("altered witness status=%d: %s", w.Code, w.Body.String())
	}
	if row, _ := db.LoadFindingPoC(s.DB, f.ID); row != nil {
		t.Fatal("corrupt witness persisted")
	}
	if w := witnessReq(t, s, "POST", f.ID, archive, true); w.Code != 201 {
		t.Fatalf("valid retry: %d %s", w.Code, w.Body.String())
	}
	// Existing captures are immutable: different bytes cannot overwrite them.
	if w := witnessReq(t, s, "POST", f.ID, bad, true); w.Code != 422 {
		t.Fatalf("corrupt overwrite: %d", w.Code)
	}
	if w := witnessReq(t, s, "POST", f.ID, archive, true); w.Code != 200 {
		t.Fatalf("idempotent conflict: %d", w.Code)
	}
	if w := witnessReq(t, s, "POST", f.ID, make([]byte, rizzerWitnessMaxBytes+1), true); w.Code != 413 {
		t.Fatalf("oversize payload status=%d", w.Code)
	}
	// Imported non-Rizzer reports cannot attach the same witness.
	var foreign db.Finding
	if err := s.DB.Model(&db.Finding{}).Where("id = ?", f.ID).Update("imported_from", "different tool").Error; err != nil {
		t.Fatal(err)
	}
	if err := s.DB.First(&foreign, f.ID).Error; err != nil {
		t.Fatal(err)
	}
	if w := witnessReq(t, s, "POST", foreign.ID, archive, true); w.Code != 422 {
		t.Fatalf("foreign report status=%d", w.Code)
	}
}

func TestRizzerWitnessRealCampaignContract(t *testing.T) {
	sarifPath, witnessPath := os.Getenv("RIZZER_SARIF_PROOF"), os.Getenv("RIZZER_WITNESS_PROOF")
	if sarifPath == "" || witnessPath == "" {
		t.Skip("set RIZZER_SARIF_PROOF and RIZZER_WITNESS_PROOF for locally generated synthetic campaign")
	}
	report, err := os.ReadFile(sarifPath)
	if err != nil {
		t.Fatal(err)
	}
	witness, err := os.ReadFile(witnessPath)
	if err != nil {
		t.Fatal(err)
	}
	s, done := newTestServer(t)
	defer done()
	w := postImport(t, s, "/api/v1/import?revalidate=false", string(report))
	if w.Code != http.StatusCreated {
		t.Fatalf("real SARIF import status=%d: %s", w.Code, w.Body.String())
	}
	var finding db.Finding
	if err := s.DB.First(&finding).Error; err != nil {
		t.Fatal(err)
	}
	w = witnessReq(t, s, http.MethodPost, finding.ID, witness, true)
	if w.Code != http.StatusCreated {
		t.Fatalf("real witness POST=%d: %s", w.Code, w.Body.String())
	}
	downloaded := witnessReq(t, s, http.MethodGet, finding.ID, nil, false)
	if downloaded.Code != http.StatusOK || !bytes.Equal(downloaded.Body.Bytes(), witness) {
		t.Fatalf("real witness GET=%d bytes=%d", downloaded.Code, downloaded.Body.Len())
	}
	t.Logf("PASS real Rizzer synthetic SARIF-to-PoC attachment and retrieval: finding=%d bytes=%d sha256=%s", finding.ID, len(witness), rizzerDigest(witness))
}
