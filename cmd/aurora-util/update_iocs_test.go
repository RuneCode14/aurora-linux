package main

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// mockGitHubServer creates an httptest server that serves a fake GitHub
// release API and a tarball containing the given files. Returns the
// server and a cleanup function that restores githubAPIBase.
func mockGitHubServer(t *testing.T, releaseTag string, archiveFiles map[string]string) (*httptest.Server, func()) {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/releases/latest") || strings.Contains(r.URL.Path, "/releases/tags/"):
			json.NewEncoder(w).Encode(githubRelease{
				TagName:    releaseTag,
				Name:       "Release " + releaseTag,
				TarballURL: "http://" + r.Host + "/tarball/" + releaseTag,
			})
		case strings.Contains(r.URL.Path, "/tarball/"):
			w.Header().Set("Content-Type", "application/gzip")
			writeTarGzResponse(t, w, archiveFiles)
		default:
			http.NotFound(w, r)
		}
	}))

	oldBase := githubAPIBase
	githubAPIBase = server.URL
	cleanup := func() {
		githubAPIBase = oldBase
		server.Close()
	}

	return server, cleanup
}

func writeTarGzResponse(t *testing.T, w http.ResponseWriter, files map[string]string) {
	t.Helper()
	gw := gzip.NewWriter(w)
	defer gw.Close()
	tw := tar.NewWriter(gw)
	defer tw.Close()

	for name, content := range files {
		hdr := &tar.Header{
			Name: name,
			Mode: 0644,
			Size: int64(len(content)),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("tar.WriteHeader() error = %v", err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatalf("tar.Write() error = %v", err)
		}
	}
}

// ---------------------------------------------------------------------------
// TestUpdateIOCsDryRun
// ---------------------------------------------------------------------------

func TestUpdateIOCsDryRun(t *testing.T) {
	_, cleanup := mockGitHubServer(t, "v2.1", map[string]string{
		"signature-base-v2.1/iocs/c2-iocs.txt":       "# C2 IOCs\nevil.com\n",
		"signature-base-v2.1/iocs/filename-iocs.txt":  "# Filename IOCs\n\\\\evil\\.exe;80\n",
		"signature-base-v2.1/iocs/hash-iocs.txt":      "# Hash IOCs\n",
		"signature-base-v2.1/iocs/keywords.txt":        "# Keywords\n",
		"signature-base-v2.1/yara/apt_example.yar":     "rule apt { condition: true }",
	})
	defer cleanup()

	tmpDir := t.TempDir()
	opts := signaturesOptions{
		IOCRepo:    "Neo23x0/signature-base",
		IOCVersion: "latest",
		IOCDir:     filepath.Join(tmpDir, "iocs"),
		IOCSubdir:  "iocs",
		DryRun:     true,
		SkipSigma:  true,
		SkipIOCs:   false,
	}

	client := &http.Client{}
	err := updateIOCs(context.Background(), client, "", opts)
	if err != nil {
		t.Fatalf("updateIOCs(dry-run) error = %v", err)
	}

	// Dry-run: destination directory should NOT exist
	if _, err := os.Stat(opts.IOCDir); !os.IsNotExist(err) {
		t.Fatalf("dry-run should not create IOC directory, stat err = %v", err)
	}
}

// ---------------------------------------------------------------------------
// TestUpdateIOCsEndToEnd
// ---------------------------------------------------------------------------

func TestUpdateIOCsEndToEnd(t *testing.T) {
	_, cleanup := mockGitHubServer(t, "v2.1", map[string]string{
		"signature-base-v2.1/iocs/c2-iocs.txt":       "# C2 IOCs\nevil.com\n10.0.0.1;90\n",
		"signature-base-v2.1/iocs/filename-iocs.txt":  "# Filename IOCs\n\\\\evil\\.exe;80\n",
		"signature-base-v2.1/iocs/hash-iocs.txt":      "# Hash IOCs\nabc123hash\n",
		"signature-base-v2.1/iocs/keywords.txt":        "# Keywords\nsuspicious_keyword\n",
		"signature-base-v2.1/yara/apt_example.yar":     "rule apt { condition: true }",
		"signature-base-v2.1/README.md":                 "# Signature Base",
	})
	defer cleanup()

	tmpDir := t.TempDir()
	iocsDir := filepath.Join(tmpDir, "iocs")

	opts := signaturesOptions{
		IOCRepo:    "Neo23x0/signature-base",
		IOCVersion: "latest",
		IOCDir:     iocsDir,
		IOCSubdir:  "iocs",
		DryRun:     false,
		SkipSigma:  true,
	}

	client := &http.Client{}
	err := updateIOCs(context.Background(), client, "", opts)
	if err != nil {
		t.Fatalf("updateIOCs() error = %v", err)
	}

	// Verify IOC files were written
	expectedFiles := []string{"c2-iocs.txt", "filename-iocs.txt", "hash-iocs.txt", "keywords.txt"}
	for _, name := range expectedFiles {
		path := filepath.Join(iocsDir, name)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			t.Errorf("expected IOC file %s to exist", name)
		}
	}

	// Verify c2-iocs content
	c2Content, err := os.ReadFile(filepath.Join(iocsDir, "c2-iocs.txt"))
	if err != nil {
		t.Fatalf("ReadFile(c2-iocs.txt) error = %v", err)
	}
	if !strings.Contains(string(c2Content), "evil.com") {
		t.Errorf("c2-iocs.txt should contain evil.com, got: %s", c2Content)
	}
	if !strings.Contains(string(c2Content), "10.0.0.1;90") {
		t.Errorf("c2-iocs.txt should contain scored entry, got: %s", c2Content)
	}

	// Verify YARA files were NOT extracted (only iocs/ subdir)
	yaraPath := filepath.Join(iocsDir, "apt_example.yar")
	if _, err := os.Stat(yaraPath); !os.IsNotExist(err) {
		t.Errorf("YARA files should not be in IOC directory")
	}

	// Verify SOURCE.txt metadata was written
	sourcePath := filepath.Join(iocsDir, "SOURCE.txt")
	sourceContent, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatalf("ReadFile(SOURCE.txt) error = %v", err)
	}
	sourceStr := string(sourceContent)
	if !strings.Contains(sourceStr, "Neo23x0/signature-base") {
		t.Errorf("SOURCE.txt should contain repo name, got: %s", sourceStr)
	}
	if !strings.Contains(sourceStr, "v2.1") {
		t.Errorf("SOURCE.txt should contain release tag, got: %s", sourceStr)
	}
}

// ---------------------------------------------------------------------------
// TestUpdateIOCsReplacesExistingFiles
// ---------------------------------------------------------------------------

func TestUpdateIOCsReplacesExistingFiles(t *testing.T) {
	_, cleanup := mockGitHubServer(t, "v3.0", map[string]string{
		"signature-base-v3.0/iocs/c2-iocs.txt":       "# Updated C2\nnew-evil.com\n",
		"signature-base-v3.0/iocs/filename-iocs.txt":  "# Updated Filename\n\\\\new\\.exe;90\n",
	})
	defer cleanup()

	tmpDir := t.TempDir()
	iocsDir := filepath.Join(tmpDir, "iocs")

	// Pre-populate with old content
	os.MkdirAll(iocsDir, 0755)
	os.WriteFile(filepath.Join(iocsDir, "c2-iocs.txt"), []byte("# Old C2\nold-evil.com\n"), 0644)
	os.WriteFile(filepath.Join(iocsDir, "stale-file.txt"), []byte("should be removed"), 0644)

	opts := signaturesOptions{
		IOCRepo:    "Neo23x0/signature-base",
		IOCVersion: "latest",
		IOCDir:     iocsDir,
		IOCSubdir:  "iocs",
		DryRun:     false,
		SkipSigma:  true,
	}

	client := &http.Client{}
	err := updateIOCs(context.Background(), client, "", opts)
	if err != nil {
		t.Fatalf("updateIOCs() error = %v", err)
	}

	// New content should be present
	c2Content, _ := os.ReadFile(filepath.Join(iocsDir, "c2-iocs.txt"))
	if !strings.Contains(string(c2Content), "new-evil.com") {
		t.Errorf("c2-iocs.txt should contain new content, got: %s", c2Content)
	}
	if strings.Contains(string(c2Content), "old-evil.com") {
		t.Errorf("c2-iocs.txt should not contain old content")
	}

	// Stale file should be gone (directory was replaced)
	if _, err := os.Stat(filepath.Join(iocsDir, "stale-file.txt")); !os.IsNotExist(err) {
		t.Errorf("stale file should have been removed by directory replacement")
	}

	// Backup should exist
	entries, _ := os.ReadDir(tmpDir)
	backupFound := false
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "iocs.bak.") {
			backupFound = true
			// Old file should be in backup
			oldContent, _ := os.ReadFile(filepath.Join(tmpDir, e.Name(), "c2-iocs.txt"))
			if !strings.Contains(string(oldContent), "old-evil.com") {
				t.Errorf("backup should contain old content, got: %s", oldContent)
			}
			break
		}
	}
	if !backupFound {
		t.Errorf("expected backup directory to exist")
	}
}

// ---------------------------------------------------------------------------
// TestUpdateSignaturesSkipFlags
// ---------------------------------------------------------------------------

func TestUpdateSignaturesBothSkipReturnsError(t *testing.T) {
	opts := signaturesOptions{
		SkipSigma: true,
		SkipIOCs:  true,
	}

	err := runUpdateSignatures(context.Background(), opts)
	if err == nil {
		t.Fatal("expected error when both --skip-sigma and --skip-iocs are set")
	}
	if !strings.Contains(err.Error(), "cannot use --skip-sigma and --skip-iocs together") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestUpdateSignaturesSkipSigmaOnlyRunsIOCs(t *testing.T) {
	_, cleanup := mockGitHubServer(t, "v2.1", map[string]string{
		"signature-base-v2.1/iocs/c2-iocs.txt":      "# C2\nevil.com\n",
		"signature-base-v2.1/iocs/filename-iocs.txt": "# Filename\n\\\\evil\\.exe;80\n",
	})
	defer cleanup()

	tmpDir := t.TempDir()
	iocsDir := filepath.Join(tmpDir, "iocs")
	rulesDir := filepath.Join(tmpDir, "rules")

	opts := signaturesOptions{
		Repo:      "SigmaHQ/sigma",
		RulesDir:  rulesDir,
		IOCRepo:   "Neo23x0/signature-base",
		IOCDir:    iocsDir,
		IOCSubdir: "iocs",
		SkipSigma: true,
		SkipIOCs:  false,
		IOCVersion: "latest",
		Version:    "latest",
	}

	err := runUpdateSignatures(context.Background(), opts)
	if err != nil {
		t.Fatalf("runUpdateSignatures() error = %v", err)
	}

	// IOCs should exist
	if _, err := os.Stat(filepath.Join(iocsDir, "c2-iocs.txt")); os.IsNotExist(err) {
		t.Error("IOC files should have been created")
	}

	// Sigma rules should NOT exist (skipped)
	if _, err := os.Stat(rulesDir); !os.IsNotExist(err) {
		t.Error("Sigma rules directory should not exist when --skip-sigma is set")
	}
}

func TestUpdateSignaturesSkipIOCsOnlyRunsSigma(t *testing.T) {
	_, cleanup := mockGitHubServer(t, "r2026-01-01", map[string]string{
		"sigma-r2026-01-01/rules/linux/proc_creation/test.yml": "title: Test\n",
		"sigma-r2026-01-01/rules/linux/builtin/test2.yml":      "title: Test2\n",
	})
	defer cleanup()

	tmpDir := t.TempDir()
	iocsDir := filepath.Join(tmpDir, "sigma-rules", "iocs")
	rulesDir := filepath.Join(tmpDir, "sigma-rules", "rules", "linux")

	opts := signaturesOptions{
		Repo:         "SigmaHQ/sigma",
		Version:      "latest",
		RulesDir:     rulesDir,
		SourceSubdir: "rules/linux",
		IOCRepo:      "Neo23x0/signature-base",
		IOCDir:       iocsDir,
		IOCSubdir:    "iocs",
		SkipSigma:    false,
		SkipIOCs:     true,
		IOCVersion:   "latest",
	}

	err := runUpdateSignatures(context.Background(), opts)
	if err != nil {
		t.Fatalf("runUpdateSignatures() error = %v", err)
	}

	// Sigma rules should exist
	if _, err := os.Stat(filepath.Join(rulesDir, "proc_creation", "test.yml")); os.IsNotExist(err) {
		t.Error("Sigma rule files should have been created")
	}

	// IOCs should NOT exist (skipped)
	if _, err := os.Stat(iocsDir); !os.IsNotExist(err) {
		t.Error("IOC directory should not exist when --skip-iocs is set")
	}
}

// ---------------------------------------------------------------------------
// TestUpdateIOCsSpecificVersion
// ---------------------------------------------------------------------------

func TestUpdateIOCsSpecificVersion(t *testing.T) {
	_, cleanup := mockGitHubServer(t, "v1.5", map[string]string{
		"signature-base-v1.5/iocs/c2-iocs.txt":      "# C2 v1.5\nold-evil.com\n",
		"signature-base-v1.5/iocs/filename-iocs.txt": "# Filename v1.5\n\\\\old\\.exe;70\n",
	})
	defer cleanup()

	tmpDir := t.TempDir()
	iocsDir := filepath.Join(tmpDir, "iocs")

	opts := signaturesOptions{
		IOCRepo:    "Neo23x0/signature-base",
		IOCVersion: "v1.5",
		IOCDir:     iocsDir,
		IOCSubdir:  "iocs",
		DryRun:     false,
		SkipSigma:  true,
	}

	client := &http.Client{}
	err := updateIOCs(context.Background(), client, "", opts)
	if err != nil {
		t.Fatalf("updateIOCs(v1.5) error = %v", err)
	}

	sourceContent, _ := os.ReadFile(filepath.Join(iocsDir, "SOURCE.txt"))
	if !strings.Contains(string(sourceContent), "v1.5") {
		t.Errorf("SOURCE.txt should reference v1.5, got: %s", sourceContent)
	}
}
