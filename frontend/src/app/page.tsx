import Link from "next/link";

export default function LandingPage() {
  return (
    <main className="min-h-screen bg-bg-primary text-text-primary font-body">
      {/* Nav */}
      <nav className="flex items-center justify-between px-8 py-5 border-b border-border">
        <span className="text-accent-primary font-display font-bold text-xl tracking-tight">VEXIS</span>
        <Link
          href="/scan/new"
          className="px-5 py-2 bg-accent-primary text-bg-primary font-bold text-sm rounded-lg hover:opacity-90 transition-opacity"
        >
          Try it now →
        </Link>
      </nav>

      {/* Hero */}
      <section className="flex flex-col items-center justify-center text-center px-8 pt-16 md:pt-24 pb-12 md:pb-20">
        <div className="inline-block px-3 py-1 bg-bg-elevated border border-border rounded-full text-xs text-text-muted mb-6 font-code">
          AI-Powered Zero-Day Discovery
        </div>
        <h1 className="text-4xl md:text-6xl font-display font-bold leading-tight max-w-3xl">
          Every scanner{" "}
          <span className="text-text-muted">matches patterns.</span>
          <br />
          <span className="text-accent-primary">VEXIS reasons.</span>
        </h1>
        <p className="mt-6 text-lg text-text-secondary max-w-xl">
          Point it at any Python codebase. It finds vulnerabilities no scanner has ever seen —
          by combining deterministic taint analysis with LLM-powered semantic reasoning.
        </p>
        <div className="flex gap-4 mt-10">
          <Link
            href="/scan/new"
            className="px-8 py-4 bg-accent-primary text-bg-primary font-bold rounded-lg hover:opacity-90 transition-opacity text-sm"
          >
            Start a free scan →
          </Link>
          <Link
            href="/dashboard"
            className="px-8 py-4 border border-border text-text-secondary rounded-lg hover:border-accent-primary hover:text-text-primary transition-colors text-sm"
          >
            View dashboard
          </Link>
        </div>
      </section>

      {/* What others miss */}
      <section className="max-w-5xl mx-auto px-8 pb-20">
        <div className="text-center mb-12">
          <h2 className="text-3xl font-display font-bold">What every other scanner misses</h2>
          <p className="text-text-muted mt-2 text-sm">A vulnerability spanning 3 files — invisible to pattern-matching tools.</p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 mb-6">
          {/* File 1 */}
          <div className="bg-bg-secondary border border-border rounded-lg overflow-hidden">
            <div className="px-4 py-2 border-b border-border flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-severity-info" />
              <span className="font-code text-xs text-text-muted">middleware/rate_limiter.py</span>
            </div>
            <pre className="px-4 py-3 text-xs font-code leading-relaxed overflow-x-auto">
              <span className="text-text-muted"># Sets client_id from header{"\n"}</span>
              <span className="text-text-secondary">def </span>
              <span className="text-accent-primary">check_rate_limit</span>
              <span className="text-text-secondary">(request):{"\n"}</span>
              <span className="text-text-secondary">  client_id = request.headers</span>
              <span className="text-text-secondary">{"\n"}</span>
              <span className="text-text-secondary">    .get(</span>
              <span className="text-severity-critical">"X-Client-ID"</span>
              <span className="text-text-secondary">){"\n"}</span>
              <span className="text-text-secondary">  request.state.client_id{"\n"}</span>
              <span className="text-text-secondary">    = client_id{"\n"}</span>
              <span className="text-text-muted">  # stored in "trusted" state</span>
            </pre>
          </div>

          {/* File 2 */}
          <div className="bg-bg-secondary border border-border rounded-lg overflow-hidden">
            <div className="px-4 py-2 border-b border-border flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-severity-info" />
              <span className="font-code text-xs text-text-muted">handlers/search.py</span>
            </div>
            <pre className="px-4 py-3 text-xs font-code leading-relaxed overflow-x-auto">
              <span className="text-text-muted"># Sanitizes search query (safe){"\n"}</span>
              <span className="text-text-secondary">def </span>
              <span className="text-accent-primary">search</span>
              <span className="text-text-secondary">(request):{"\n"}</span>
              <span className="text-text-secondary">  query = request.query_params{"\n"}</span>
              <span className="text-text-secondary">    .get(</span>
              <span className="text-severity-critical">"q"</span>
              <span className="text-text-secondary">){"\n"}</span>
              <span className="text-text-secondary">  safe = query.replace(</span>
              <span className="text-severity-medium">"'"</span>
              <span className="text-text-secondary">, </span>
              <span className="text-severity-medium">""</span>
              <span className="text-text-secondary">){"\n"}</span>
              <span className="text-text-secondary">  log_search(</span>
              <span className="text-severity-high">client_id</span>
              <span className="text-text-secondary">, safe)</span>
            </pre>
          </div>

          {/* File 3 — the vulnerable one */}
          <div className="bg-bg-secondary border border-severity-critical rounded-lg overflow-hidden">
            <div className="px-4 py-2 border-b border-severity-critical border-opacity-30 flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-severity-critical animate-pulse" />
              <span className="font-code text-xs text-severity-critical">utils/logger.py</span>
              <span className="ml-auto text-xs text-severity-critical font-bold">VULNERABLE</span>
            </div>
            <pre className="px-4 py-3 text-xs font-code leading-relaxed overflow-x-auto">
              <span className="text-text-muted"># client_id never sanitized!{"\n"}</span>
              <span className="text-text-secondary">def </span>
              <span className="text-accent-primary">log_search</span>
              <span className="text-text-secondary">(client_id, q):{"\n"}</span>
              <span className="text-text-secondary">  db.execute({"\n"}</span>
              <span className="text-text-secondary">    </span>
              <span className="text-severity-critical">f"INSERT INTO log {"\n"}    (client_id) {"\n"}    VALUES ('{"{client_id}"}')"</span>
              <span className="text-text-secondary">{"\n"}  )</span>
            </pre>
          </div>
        </div>

        {/* Scanner comparison */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          <div className="bg-bg-secondary border border-border rounded-lg p-5">
            <div className="flex items-center gap-2 mb-3">
              <span className="text-severity-info text-sm font-bold">✗ Semgrep / CodeQL / Snyk</span>
            </div>
            <p className="text-text-muted text-sm">
              See a parameterized search query in <code className="font-code">search.py</code> — mark it safe.
              Never follow <code className="font-code">client_id</code> across the trust boundary into the logger.
            </p>
          </div>
          <div className="bg-bg-secondary border border-accent-primary rounded-lg p-5">
            <div className="flex items-center gap-2 mb-3">
              <span className="text-accent-primary text-sm font-bold">✓ VEXIS</span>
            </div>
            <p className="text-text-secondary text-sm">
              Traces <code className="font-code text-severity-critical">X-Client-ID</code> header →{" "}
              <code className="font-code">request.state</code> → <code className="font-code">log_search()</code> →{" "}
              raw SQL. Confirms bypass with payload:{" "}
              <code className="font-code text-severity-critical">'; DROP TABLE users;--</code>
            </p>
          </div>
        </div>
      </section>

      {/* Vuln classes */}
      <section className="border-t border-border py-16">
        <div className="max-w-5xl mx-auto px-8">
          <h2 className="text-2xl font-display font-bold text-center mb-10">Detected vulnerability classes</h2>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {[
              { cwe: "CWE-89", name: "SQL Injection", desc: "f-strings, concatenation, ORM raw queries" },
              { cwe: "CWE-78", name: "Command Injection", desc: "subprocess shell=True, os.system, eval" },
              { cwe: "CWE-22", name: "Path Traversal", desc: "os.path.join bypass, send_file, open()" },
              { cwe: "CWE-1336", name: "SSTI", desc: "render_template_string, Jinja2 Template()" },
              { cwe: "CWE-918", name: "SSRF", desc: "requests.get, httpx, urllib with user input" },
              { cwe: "CWE-502", name: "Insecure Deserialization", desc: "pickle.loads, yaml.load, marshal" },
              { cwe: "CWE-79", name: "XSS", desc: "Markup(), render_template_string with user data" },
            ].map(({ cwe, name, desc }) => (
              <div key={cwe} className="bg-bg-secondary border border-border rounded-lg p-5">
                <p className="font-code text-xs text-severity-critical mb-1">{cwe}</p>
                <p className="font-display font-semibold text-sm mb-2">{name}</p>
                <p className="text-text-muted text-xs">{desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* VEXIS vs Semgrep */}
      <section className="border-t border-border py-16">
        <div className="max-w-5xl mx-auto px-8">
          <div className="text-center mb-10">
            <h2 className="text-2xl font-display font-bold">VEXIS vs Semgrep</h2>
            <p className="text-text-muted mt-2 text-sm">Benchmarked on 27 samples: 21 corpus + 3 cross-file + 3 CVE</p>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-6 mb-8">
            {[
              { label: "True Positive Rate", vexis: "90%", semgrep: "67%", winner: "vexis" },
              { label: "False Positive Rate", vexis: "5%", semgrep: "10%", winner: "vexis" },
              { label: "Cross-file Detection", vexis: "Yes", semgrep: "No", winner: "vexis" },
            ].map(({ label, vexis, semgrep, winner }) => (
              <div key={label} className="bg-bg-secondary border border-border rounded-lg p-5">
                <p className="text-text-muted text-xs uppercase tracking-wider mb-3">{label}</p>
                <div className="flex items-end justify-between">
                  <div>
                    <p className="text-text-muted text-xs mb-1">Semgrep</p>
                    <p className="font-code font-bold text-text-secondary text-lg">{semgrep}</p>
                  </div>
                  <div className="text-right">
                    <p className="text-text-muted text-xs mb-1">VEXIS</p>
                    <p className={`font-code font-bold text-lg ${winner === "vexis" ? "text-accent-primary" : "text-text-secondary"}`}>{vexis}</p>
                  </div>
                </div>
              </div>
            ))}
          </div>
          <div className="bg-bg-secondary border border-accent-primary/30 rounded-lg p-5">
            <p className="text-accent-primary font-bold text-sm mb-1">Cross-file taint tracking — the key differentiator</p>
            <p className="text-text-muted text-sm">
              Semgrep and every other pattern-matching scanner operates on single files. VEXIS follows taint across
              function call boundaries — catching the class of vulnerabilities where user input enters in{" "}
              <code className="font-code text-xs">rate_limiter.py</code>, gets &quot;sanitized&quot; in{" "}
              <code className="font-code text-xs">search.py</code>, and explodes in{" "}
              <code className="font-code text-xs">logger.py</code>. No other tool does this automatically.
            </p>
          </div>
        </div>
      </section>

      {/* Chain Discovery */}
      <section className="border-t border-border py-16">
        <div className="max-w-5xl mx-auto px-8">
          <div className="text-center mb-10">
            <h2 className="text-2xl font-display font-bold">Pass 3: Attack Chain Discovery</h2>
            <p className="text-text-muted mt-2 text-sm max-w-xl mx-auto">
              Most scanners stop at individual findings. VEXIS goes further — it looks at combinations
              of low-severity paths and identifies when they can be chained into a critical attack.
            </p>
          </div>

          {/* Chain visual */}
          <div className="flex items-center justify-center gap-4 mb-10 flex-wrap">
            <div className="bg-bg-secondary border border-severity-medium/60 rounded-xl p-5 text-center w-44">
              <p className="font-code text-xs text-severity-medium mb-1">MEDIUM</p>
              <p className="font-semibold text-sm">Info Leak</p>
              <p className="text-text-muted text-xs mt-1">Exposes user ID + admin flag via SQLi</p>
            </div>
            <div className="flex flex-col items-center gap-1 text-text-muted">
              <div className="w-8 border-t-2 border-dashed border-[#7C4DFF]" />
              <span className="text-[#7C4DFF] text-xs font-code">enables</span>
            </div>
            <div className="bg-bg-secondary border border-severity-medium/60 rounded-xl p-5 text-center w-44">
              <p className="font-code text-xs text-severity-medium mb-1">MEDIUM</p>
              <p className="font-semibold text-sm">Gated SQLi</p>
              <p className="text-text-muted text-xs mt-1">Role update — admin-only, seems safe</p>
            </div>
            <div className="flex flex-col items-center gap-1 text-text-muted">
              <div className="w-8 border-t-2 border-dashed border-[#7C4DFF]" />
              <span className="text-[#7C4DFF] text-xs font-code">chain →</span>
            </div>
            <div className="bg-bg-secondary border border-severity-critical rounded-xl p-5 text-center w-44 relative">
              <div className="absolute -top-2.5 left-1/2 -translate-x-1/2 px-2 py-0.5 bg-severity-critical rounded text-bg-primary text-xs font-bold">CRITICAL</div>
              <p className="font-code text-xs text-severity-critical mb-1 mt-1">CHAIN</p>
              <p className="font-semibold text-sm">Privilege Escalation</p>
              <p className="text-text-muted text-xs mt-1">Leak admin ID → bypass guard → own the DB</p>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="bg-bg-secondary border border-border rounded-lg p-5">
              <p className="font-semibold text-sm mb-2">What other tools see</p>
              <ul className="space-y-1 text-text-muted text-sm">
                <li>✗ Finding 1: low-confidence SQLi (medium)</li>
                <li>✗ Finding 2: low-confidence SQLi (medium)</li>
                <li className="text-text-muted pt-1 text-xs">No connection between them. No escalation detected.</li>
              </ul>
            </div>
            <div className="bg-bg-secondary border border-[#7C4DFF]/40 rounded-lg p-5">
              <p className="font-semibold text-sm mb-2 text-[#7C4DFF]">What VEXIS sees</p>
              <ul className="space-y-1 text-text-secondary text-sm">
                <li>✓ Finding 1 leaks session data used by Finding 2</li>
                <li>✓ Combined attack bypasses the admin guard</li>
                <li className="text-accent-primary pt-1 text-xs font-bold">Chain finding: CRITICAL — Privilege Escalation via Info Leak</li>
              </ul>
            </div>
          </div>
        </div>
      </section>

      {/* CTA */}
      <section className="py-20 text-center border-t border-border">
        <h2 className="text-3xl font-display font-bold mb-4">Find the bugs your scanner missed.</h2>
        <p className="text-text-muted mb-8">Paste code or drop a GitHub URL. Results in under 60 seconds.</p>
        <Link
          href="/scan/new"
          className="inline-block px-10 py-4 bg-accent-primary text-bg-primary font-bold rounded-lg hover:opacity-90 transition-opacity"
        >
          Try it now — it&apos;s free →
        </Link>
      </section>

      <footer className="border-t border-border px-8 py-6 flex items-center justify-between text-xs text-text-muted">
        <span className="font-code">VEXIS — Vulnerability EXploration &amp; Inference System</span>
        <span>Phase 1 MVP</span>
      </footer>
    </main>
  );
}
