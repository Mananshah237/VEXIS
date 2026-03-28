"use client";

import { useState, useRef, DragEvent, ChangeEvent } from "react";
import { useRouter } from "next/navigation";

type TabId = "paste" | "upload" | "github";

const TABS: { id: TabId; label: string }[] = [
  { id: "paste", label: "Paste Code" },
  { id: "upload", label: "Upload File" },
  { id: "github", label: "GitHub URL" },
];

export default function NewScanPage() {
  const router = useRouter();
  const [tab, setTab] = useState<TabId>("paste");
  const [code, setCode] = useState("");
  const [language, setLanguage] = useState("python");
  const [fileName, setFileName] = useState<string | null>(null);
  const [fileContent, setFileContent] = useState<string | null>(null);
  const [githubUrl, setGithubUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [dragging, setDragging] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const apiBase = process.env.NEXT_PUBLIC_API_URL;

  function handleFileDrop(e: DragEvent<HTMLDivElement>) {
    e.preventDefault();
    setDragging(false);
    const file = e.dataTransfer.files[0];
    if (file) readFile(file);
  }

  function handleFileChange(e: ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (file) readFile(file);
  }

  function readFile(file: File) {
    setFileName(file.name);
    const reader = new FileReader();
    reader.onload = (e) => setFileContent(e.target?.result as string);
    reader.readAsText(file);
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setLoading(true);

    let body: Record<string, string>;
    if (tab === "paste") {
      if (!code.trim()) { setError("Please paste some code."); setLoading(false); return; }
      body = { source_type: "raw_code", source: code, language };
    } else if (tab === "upload") {
      if (!fileContent) { setError("Please upload a .py file."); setLoading(false); return; }
      body = { source_type: "raw_code", source: fileContent, language: "python" };
    } else {
      if (!githubUrl.trim()) { setError("Please enter a GitHub URL."); setLoading(false); return; }
      body = { source_type: "github_url", source: githubUrl };
    }

    try {
      const resp = await fetch(`${apiBase}/api/v1/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      if (!resp.ok) {
        const detail = await resp.json().catch(() => ({}));
        throw new Error(detail.detail ?? `HTTP ${resp.status}`);
      }
      const data = await resp.json();
      router.push(`/scan/${data.id}`);
    } catch (err: any) {
      setError(err.message ?? "Scan failed to start");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="min-h-screen flex items-start justify-center p-8 pt-16">
      <div className="w-full max-w-2xl">
        <div className="mb-6">
          <h1 className="text-2xl font-display font-bold">New Scan</h1>
          <p className="text-text-muted text-sm mt-1">
            Scan Python source code for vulnerabilities using taint analysis + AI reasoning.
          </p>
        </div>

        {/* Tabs */}
        <div className="flex border-b border-border mb-6">
          {TABS.map((t) => (
            <button
              key={t.id}
              onClick={() => { setTab(t.id); setError(null); }}
              className={`px-5 py-2.5 text-sm font-medium border-b-2 -mb-px transition-colors ${
                tab === t.id
                  ? "border-accent-primary text-accent-primary"
                  : "border-transparent text-text-muted hover:text-text-secondary"
              }`}
            >
              {t.label}
            </button>
          ))}
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          {/* Paste Code tab */}
          {tab === "paste" && (
            <>
              <div className="flex items-center justify-between mb-1">
                <label className="text-sm text-text-secondary">Language</label>
                <select
                  value={language}
                  onChange={(e) => setLanguage(e.target.value)}
                  className="bg-bg-elevated border border-border rounded px-3 py-1 text-sm text-text-primary"
                >
                  <option value="python">Python</option>
                  <option value="javascript" disabled>JavaScript (Phase 2)</option>
                  <option value="go" disabled>Go (Phase 2)</option>
                </select>
              </div>
              <textarea
                value={code}
                onChange={(e) => setCode(e.target.value)}
                placeholder={`# Paste your Python code here\n\nfrom flask import request\nimport sqlite3\n\n@app.route('/search')\ndef search():\n    q = request.args.get('q')\n    db.execute(f"SELECT * FROM items WHERE name = '{q}'")`}
                rows={18}
                className="w-full bg-bg-elevated border border-border rounded-lg px-4 py-3 text-text-primary font-code text-sm placeholder-text-muted resize-none focus:outline-none focus:border-accent-primary transition-colors"
                required
              />
            </>
          )}

          {/* Upload File tab */}
          {tab === "upload" && (
            <div
              onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
              onDragLeave={() => setDragging(false)}
              onDrop={handleFileDrop}
              onClick={() => fileInputRef.current?.click()}
              className={`border-2 border-dashed rounded-xl p-12 text-center cursor-pointer transition-colors ${
                dragging
                  ? "border-accent-primary bg-accent-primary/5"
                  : fileName
                  ? "border-severity-safe bg-severity-safe/5"
                  : "border-border hover:border-accent-primary/50"
              }`}
            >
              <input
                ref={fileInputRef}
                type="file"
                accept=".py"
                onChange={handleFileChange}
                className="hidden"
              />
              {fileName ? (
                <>
                  <p className="text-severity-safe font-code text-lg mb-1">✓ {fileName}</p>
                  <p className="text-text-muted text-sm">Click to choose a different file</p>
                </>
              ) : (
                <>
                  <p className="text-4xl mb-3">⬆</p>
                  <p className="text-text-secondary mb-1">Drop a <span className="font-code">.py</span> file here</p>
                  <p className="text-text-muted text-sm">or click to browse</p>
                </>
              )}
            </div>
          )}

          {/* GitHub URL tab */}
          {tab === "github" && (
            <>
              <div>
                <label className="block text-sm text-text-secondary mb-2">Repository URL</label>
                <input
                  type="url"
                  value={githubUrl}
                  onChange={(e) => setGithubUrl(e.target.value)}
                  placeholder="https://github.com/username/repository"
                  className="w-full bg-bg-elevated border border-border rounded-lg px-4 py-3 text-text-primary font-code text-sm placeholder-text-muted focus:outline-none focus:border-accent-primary transition-colors"
                />
              </div>
              <p className="text-text-muted text-xs">
                VEXIS will clone the repository and scan all Python files. Large repos may take up to 5 minutes.
              </p>
            </>
          )}

          {error && (
            <div className="bg-severity-critical/10 border border-severity-critical/30 rounded-lg px-4 py-3 text-severity-critical text-sm">
              {error}
            </div>
          )}

          <button
            type="submit"
            disabled={loading}
            className="w-full py-3 bg-accent-primary text-bg-primary font-bold rounded-lg disabled:opacity-50 hover:opacity-90 transition-opacity"
          >
            {loading ? "Starting scan..." : "Scan →"}
          </button>
        </form>
      </div>
    </div>
  );
}
