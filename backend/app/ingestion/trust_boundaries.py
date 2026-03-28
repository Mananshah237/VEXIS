"""
Trust boundary definitions — sources, sinks, and sanitizers for Python.
"""
from dataclasses import dataclass, field


@dataclass
class SourcePattern:
    pattern: str
    trust_level: int = 0  # 0=untrusted
    source_type: str = "http_param"
    description: str = ""


@dataclass
class SinkPattern:
    pattern: str
    vuln_class: str
    severity: str = "high"
    description: str = ""


@dataclass
class SanitizerPattern:
    pattern: str
    clears_for: list[str] = field(default_factory=list)  # kept for backward compat
    is_partial: bool = False
    description: str = ""
    effective_for: list[str] = field(default_factory=list)  # which vuln_classes this actually protects


TAINT_SOURCES: list[SourcePattern] = [
    SourcePattern("request.get", source_type="http_param", description="Flask GET param"),
    SourcePattern("request.args.get", source_type="http_param", description="Flask query param"),
    SourcePattern("request.form.get", source_type="http_param", description="Flask form data"),
    SourcePattern("request.form", source_type="http_param", description="Flask form dict"),
    SourcePattern("request.args", source_type="http_param", description="Flask args dict"),
    SourcePattern("request.json", source_type="http_body", description="Flask JSON body"),
    SourcePattern("request.data", source_type="http_body", description="Flask raw body"),
    SourcePattern("request.cookies.get", source_type="http_cookie", description="Flask cookie"),
    SourcePattern("request.headers.get", source_type="http_header", description="Flask header"),
    SourcePattern("request.values.get", source_type="http_param", description="Flask combined"),
    SourcePattern("request.query_params.get", source_type="http_param", description="Starlette/FastAPI query param"),
    SourcePattern("request.query_params", source_type="http_param", description="Starlette query params dict"),
    SourcePattern("sys.argv", source_type="cli_arg", description="CLI arguments"),
    SourcePattern("input(", source_type="user_input", description="stdin input"),
    SourcePattern("os.environ.get", source_type="env_var", description="Environment variable"),
    # FastAPI
    SourcePattern("Query(", source_type="http_param", description="FastAPI query param"),
    SourcePattern("Path(", source_type="http_param", description="FastAPI path param"),
    SourcePattern("Body(", source_type="http_body", description="FastAPI body"),
    SourcePattern("Header(", source_type="http_header", description="FastAPI header"),
    SourcePattern("request.files", source_type="http_upload", description="Flask file upload"),
]

TAINT_SINKS: list[SinkPattern] = [
    # SQL Injection
    SinkPattern("cursor.execute", vuln_class="sqli", severity="critical", description="Raw SQL execution"),
    SinkPattern("cursor.executemany", vuln_class="sqli", severity="critical"),
    SinkPattern("db.execute", vuln_class="sqli", severity="critical"),
    SinkPattern("engine.execute", vuln_class="sqli", severity="critical"),
    SinkPattern("session.execute", vuln_class="sqli", severity="critical"),
    SinkPattern(".raw(", vuln_class="sqli", severity="high", description="Django raw SQL"),
    SinkPattern(".extra(", vuln_class="sqli", severity="high", description="Django extra"),

    # Command Injection
    SinkPattern("os.system(", vuln_class="cmdi", severity="critical", description="Shell command"),
    SinkPattern("os.popen(", vuln_class="cmdi", severity="critical"),
    SinkPattern("subprocess.call(", vuln_class="cmdi", severity="critical"),
    SinkPattern("subprocess.run(", vuln_class="cmdi", severity="critical"),
    SinkPattern("subprocess.Popen(", vuln_class="cmdi", severity="critical"),
    SinkPattern("subprocess.check_output(", vuln_class="cmdi", severity="critical"),
    SinkPattern("eval(", vuln_class="cmdi", severity="critical", description="Python eval"),
    SinkPattern("exec(", vuln_class="cmdi", severity="critical", description="Python exec"),

    # Path Traversal
    SinkPattern("open(", vuln_class="path_traversal", severity="high", description="File open"),
    SinkPattern("send_file(", vuln_class="path_traversal", severity="high", description="Flask send_file"),
    SinkPattern("send_from_directory(", vuln_class="path_traversal", severity="high"),
    SinkPattern("shutil.copy(", vuln_class="path_traversal", severity="high"),
    SinkPattern("os.remove(", vuln_class="path_traversal", severity="high"),
    SinkPattern("os.rename(", vuln_class="path_traversal", severity="high"),
    # NOTE: os.path.join and pathlib.Path are NOT sinks — they are construction functions.
    # Taint propagates through them to the actual dangerous sinks above.

    # Server-Side Template Injection (CWE-1336)
    SinkPattern("render_template_string(", vuln_class="ssti", severity="critical", description="Jinja2 template from string"),
    SinkPattern("jinja2.Template(", vuln_class="ssti", severity="critical", description="Jinja2 Template constructor"),
    SinkPattern("Template(", vuln_class="ssti", severity="critical", description="Template constructor (Jinja2/Mako/etc.)"),

    # Server-Side Request Forgery (CWE-918)
    SinkPattern("requests.get(", vuln_class="ssrf", severity="critical", description="HTTP GET with attacker URL"),
    SinkPattern("requests.post(", vuln_class="ssrf", severity="critical", description="HTTP POST to attacker URL"),
    SinkPattern("requests.put(", vuln_class="ssrf", severity="critical"),
    SinkPattern("requests.request(", vuln_class="ssrf", severity="critical"),
    SinkPattern("urllib.request.urlopen(", vuln_class="ssrf", severity="critical", description="urllib open attacker URL"),
    SinkPattern("httpx.get(", vuln_class="ssrf", severity="critical"),
    SinkPattern("httpx.post(", vuln_class="ssrf", severity="critical"),
    SinkPattern("session.get(", vuln_class="ssrf", severity="high", description="aiohttp session GET"),
    SinkPattern("session.post(", vuln_class="ssrf", severity="high", description="aiohttp session POST"),

    # Insecure Deserialization (CWE-502)
    SinkPattern("pickle.loads(", vuln_class="deserialization", severity="critical", description="Pickle deserialization"),
    SinkPattern("pickle.load(", vuln_class="deserialization", severity="critical"),
    SinkPattern("yaml.load(", vuln_class="deserialization", severity="critical", description="Unsafe YAML load"),
    SinkPattern("yaml.unsafe_load(", vuln_class="deserialization", severity="critical"),
    SinkPattern("marshal.loads(", vuln_class="deserialization", severity="critical"),
    SinkPattern("shelve.open(", vuln_class="deserialization", severity="high"),

    # Cross-Site Scripting (CWE-79)
    SinkPattern("Markup(", vuln_class="xss", severity="high", description="Jinja2 Markup — bypasses auto-escaping"),
    SinkPattern("render_template_string(", vuln_class="xss", severity="high"),  # Also SSTI; XSS is secondary
]

SANITIZERS: list[SanitizerPattern] = [
    # SQLi sanitizers — parameterized queries (only protect against SQLi)
    SanitizerPattern('?", (', clears_for=["sqli"], effective_for=["sqli"], description="SQLite ? placeholder with tuple params (double quotes)"),
    SanitizerPattern("?', (", clears_for=["sqli"], effective_for=["sqli"], description="SQLite ? placeholder with tuple params (single quotes)"),
    SanitizerPattern('?", [', clears_for=["sqli"], effective_for=["sqli"], description="SQLite ? placeholder with list params"),
    SanitizerPattern('%s", (', clears_for=["sqli"], effective_for=["sqli"], description="DB-API %s placeholder with tuple params"),
    SanitizerPattern("%s', (", clears_for=["sqli"], effective_for=["sqli"], description="DB-API %s placeholder with tuple params"),
    SanitizerPattern('execute(%s,', clears_for=["sqli"], effective_for=["sqli"], description="DB-API %s direct"),
    SanitizerPattern("execute(%s,", clears_for=["sqli"], effective_for=["sqli"], description="DB-API %s direct"),
    SanitizerPattern(".filter(", clears_for=["sqli"], effective_for=["sqli"], description="ORM filter (parameterized)"),
    SanitizerPattern(".filter_by(", clears_for=["sqli"], effective_for=["sqli"], description="ORM filter_by"),

    # CMDi sanitizers (only protect against command injection)
    SanitizerPattern("shlex.quote(", clears_for=["cmdi"], effective_for=["cmdi"], description="Shell quoting"),
    SanitizerPattern("shlex.split(", clears_for=["cmdi"], effective_for=["cmdi"], description="Shell split"),

    # Path traversal sanitizers (only protect against path traversal)
    SanitizerPattern(
        "os.path.realpath(",
        clears_for=[],
        is_partial=True,
        effective_for=["path_traversal"],
        description="Resolves symlinks but still needs startswith(SAFE_DIR) prefix check",
    ),
    SanitizerPattern("os.path.abspath(", clears_for=[], is_partial=True,
                     effective_for=["path_traversal"],
                     description="Normalizes path but needs prefix check to be safe"),

    # XSS sanitizers — ONLY protect against XSS, NOT SQLi or CMDi
    SanitizerPattern("html.escape(", clears_for=["xss"], effective_for=["xss"], description="HTML escaping (XSS only)"),
    SanitizerPattern("markupsafe.escape(", clears_for=["xss"], effective_for=["xss"], description="Markupsafe escape (XSS only)"),
    SanitizerPattern("escape(", clears_for=["xss"], effective_for=["xss"], description="Generic escape function (XSS only)"),
    SanitizerPattern("bleach.clean(", clears_for=["xss"], effective_for=["xss"], description="Bleach HTML sanitizer (XSS only)"),
    SanitizerPattern("DOMPurify.sanitize(", clears_for=["xss"], effective_for=["xss"], description="DOMPurify (XSS only)"),

    # Deserialization sanitizers
    SanitizerPattern("yaml.safe_load(", clears_for=["deserialization"], effective_for=["deserialization"], description="Safe YAML loading"),
    SanitizerPattern("SafeLoader", clears_for=["deserialization"], effective_for=["deserialization"], description="YAML SafeLoader"),

    # SSRF sanitizers
    SanitizerPattern("urlparse(", clears_for=[], is_partial=True, effective_for=["ssrf"], description="URL parsing (partial — needs allowlist check)"),
    SanitizerPattern(".hostname", clears_for=[], is_partial=True, effective_for=["ssrf"], description="Hostname extraction (partial)"),
    SanitizerPattern("urllib.parse.quote(", clears_for=[], is_partial=True, effective_for=["ssrf"], description="URL encoding (partial)"),

    # SSTI sanitizers
    SanitizerPattern("SandboxedEnvironment", clears_for=["ssti"], effective_for=["ssti"], description="Jinja2 sandboxed environment"),

    # Numeric type casting — effective for ALL injection types (output is non-injectable)
    SanitizerPattern("int(", clears_for=["sqli", "cmdi", "path_traversal", "ssrf", "ssti", "xss"],
                     effective_for=["sqli", "cmdi", "path_traversal", "ssrf", "ssti", "xss"],
                     description="Integer cast — output is always numeric, cannot be injected"),
    SanitizerPattern("float(", clears_for=["sqli", "cmdi", "path_traversal", "ssrf", "ssti", "xss"],
                     effective_for=["sqli", "cmdi", "path_traversal", "ssrf", "ssti", "xss"],
                     description="Float cast — output is always numeric"),
]


# ─── JavaScript / TypeScript ────────────────────────────────────────────────

JS_TAINT_SOURCES: list[SourcePattern] = [
    # Express.js
    SourcePattern("req.params", source_type="http_param", description="Express route params"),
    SourcePattern("req.query", source_type="http_param", description="Express query string"),
    SourcePattern("req.body", source_type="http_body", description="Express request body"),
    SourcePattern("req.headers", source_type="http_header", description="Express headers"),
    SourcePattern("req.cookies", source_type="http_cookie", description="Express cookies"),
    # Generic Node.js
    SourcePattern("process.argv", source_type="cli_arg", description="CLI arguments"),
    SourcePattern("process.env", source_type="env_var", description="Environment variables"),
    SourcePattern("readline.question", source_type="user_input", description="stdin readline"),
    SourcePattern("prompt(", source_type="user_input", description="Browser prompt"),
]

JS_TAINT_SINKS: list[SinkPattern] = [
    # SQL Injection
    SinkPattern("db.query(", vuln_class="sqli", severity="critical", description="Node DB query"),
    SinkPattern("connection.query(", vuln_class="sqli", severity="critical"),
    SinkPattern("pool.query(", vuln_class="sqli", severity="critical"),
    SinkPattern("sequelize.query(", vuln_class="sqli", severity="critical"),
    SinkPattern("knex.raw(", vuln_class="sqli", severity="critical"),
    SinkPattern(".query(`", vuln_class="sqli", severity="critical", description="Template literal SQL"),
    SinkPattern(".query(`SELECT", vuln_class="sqli", severity="critical"),
    # Command Injection
    SinkPattern("child_process.exec(", vuln_class="cmdi", severity="critical"),
    SinkPattern("exec(", vuln_class="cmdi", severity="critical", description="exec()"),
    SinkPattern("execSync(", vuln_class="cmdi", severity="critical"),
    SinkPattern("child_process.spawn(", vuln_class="cmdi", severity="critical"),
    SinkPattern("eval(", vuln_class="cmdi", severity="critical", description="JS eval"),
    SinkPattern("new Function(", vuln_class="cmdi", severity="critical"),
    SinkPattern("setTimeout(", vuln_class="cmdi", severity="high", description="String setTimeout"),
    SinkPattern("setInterval(", vuln_class="cmdi", severity="high"),
    # Path Traversal
    SinkPattern("fs.readFile(", vuln_class="path_traversal", severity="high"),
    SinkPattern("fs.readFileSync(", vuln_class="path_traversal", severity="high"),
    SinkPattern("fs.createReadStream(", vuln_class="path_traversal", severity="high"),
    SinkPattern("res.sendFile(", vuln_class="path_traversal", severity="high", description="Express sendFile"),
    # SSTI
    SinkPattern("ejs.render(", vuln_class="ssti", severity="high", description="EJS template injection"),
    SinkPattern("pug.render(", vuln_class="ssti", severity="high"),
    SinkPattern("Handlebars.compile(", vuln_class="ssti", severity="high"),
    # SSRF
    SinkPattern("fetch(", vuln_class="ssrf", severity="high", description="Fetch API"),
    SinkPattern("axios.get(", vuln_class="ssrf", severity="high"),
    SinkPattern("axios.post(", vuln_class="ssrf", severity="high"),
    SinkPattern("http.request(", vuln_class="ssrf", severity="high"),
    # XSS
    SinkPattern("res.send(", vuln_class="xss", severity="high", description="Express res.send"),
    SinkPattern("res.write(", vuln_class="xss", severity="high"),
    SinkPattern("innerHTML", vuln_class="xss", severity="high"),
    SinkPattern("document.write(", vuln_class="xss", severity="critical"),
    # Insecure Deserialization
    SinkPattern("unserialize(", vuln_class="deserialization", severity="critical", description="node-serialize"),
    SinkPattern("js-yaml.load(", vuln_class="deserialization", severity="high"),
]

JS_SANITIZERS: list[SanitizerPattern] = [
    # SQLi — parameterized queries
    # Note: "?, [" misses cases like "?', [" where the ? is inside a quoted string
    # Use "query('" and 'query("' to detect literal-string first argument (parameterized)
    SanitizerPattern("query('", clears_for=["sqli"], effective_for=["sqli"],
                     description="JS query() with single-quoted string first arg = parameterized"),
    SanitizerPattern('query("', clears_for=["sqli"], effective_for=["sqli"],
                     description="JS query() with double-quoted string first arg = parameterized"),
    SanitizerPattern("?, [", clears_for=["sqli"], effective_for=["sqli"], description="MySQL ? placeholder fallback"),
    SanitizerPattern('db.query("', clears_for=["sqli"], effective_for=["sqli"], description="Literal SQL string (no template)"),
    SanitizerPattern(".where(", clears_for=["sqli"], effective_for=["sqli"], description="Knex/Sequelize where clause"),
    # CMDi — execFile also effectively prevents XSS via stdout (output is structured, not user-reflected HTML)
    SanitizerPattern("execFile(", clears_for=["cmdi", "xss"], effective_for=["cmdi", "xss"],
                     description="execFile: no shell, stdout not directly user-controlled HTML"),
    SanitizerPattern("shell-escape", clears_for=["cmdi"], effective_for=["cmdi"]),
    SanitizerPattern("shellEscape(", clears_for=["cmdi"], effective_for=["cmdi"]),
    # XSS
    SanitizerPattern("DOMPurify.sanitize(", clears_for=["xss"], effective_for=["xss"]),
    SanitizerPattern("escape-html", clears_for=["xss"], effective_for=["xss"]),
    SanitizerPattern("he.encode(", clears_for=["xss"], effective_for=["xss"]),
    SanitizerPattern("escapeHtml(", clears_for=["xss"], effective_for=["xss"]),
    # Path traversal
    SanitizerPattern("path.resolve(", clears_for=[], is_partial=True, effective_for=["path_traversal"],
                     description="path.resolve() — needs startsWith check to be effective"),
    SanitizerPattern(".startsWith(", clears_for=[], is_partial=True, effective_for=["path_traversal"],
                     description="startsWith check — needs path.resolve() too"),
    # SSRF
    SanitizerPattern("new URL(", clears_for=[], is_partial=True, effective_for=["ssrf"],
                     description="URL parsing — needs allowlist check"),
    SanitizerPattern(".hostname", clears_for=[], is_partial=True, effective_for=["ssrf"]),
    # Numeric type casting
    SanitizerPattern("parseInt(", clears_for=["sqli", "cmdi", "path_traversal", "ssrf", "ssti", "xss"],
                     effective_for=["sqli", "cmdi", "path_traversal", "ssrf", "ssti", "xss"],
                     description="parseInt — numeric output is safe"),
    SanitizerPattern("parseFloat(", clears_for=["sqli", "cmdi", "path_traversal", "ssrf", "ssti", "xss"],
                     effective_for=["sqli", "cmdi", "path_traversal", "ssrf", "ssti", "xss"],
                     description="parseFloat — numeric output is safe"),
    SanitizerPattern("Number(", clears_for=["sqli", "cmdi", "path_traversal", "ssrf", "ssti", "xss"],
                     effective_for=["sqli", "cmdi", "path_traversal", "ssrf", "ssti", "xss"],
                     description="Number() cast — numeric output is safe"),
]


# ─── Additional Python vuln class patterns ─────────────────────────────────

# CWE-601: Open Redirect
REDIRECT_SOURCES: list[SourcePattern] = []  # same HTTP sources as above
REDIRECT_SINKS: list[SinkPattern] = [
    SinkPattern("redirect(",           vuln_class="open_redirect", severity="medium",
                description="Flask redirect with user-controlled URL → CWE-601"),
    SinkPattern("return redirect(",    vuln_class="open_redirect", severity="medium"),
    SinkPattern('headers={"Location"', vuln_class="open_redirect", severity="medium",
                description="Raw Location header → CWE-601"),
    SinkPattern("res.redirect(",       vuln_class="open_redirect", severity="medium",
                description="Express redirect → CWE-601"),
]
REDIRECT_SANITIZERS: list[SanitizerPattern] = [
    SanitizerPattern(".startswith('/')", clears_for=["open_redirect"],
                     effective_for=["open_redirect"],
                     description="Relative URL check — prevents off-site redirect"),
    SanitizerPattern('.startswith("/")', clears_for=["open_redirect"],
                     effective_for=["open_redirect"]),
    SanitizerPattern("urlparse(", clears_for=[], is_partial=True,
                     effective_for=["open_redirect"],
                     description="URL parsing — needs netloc check to be effective"),
]

# CWE-117: Log Injection
LOG_SINKS: list[SinkPattern] = [
    SinkPattern("logging.info(",    vuln_class="log_injection", severity="low",
                description="logging.info with user data → CWE-117"),
    SinkPattern("logging.warning(", vuln_class="log_injection", severity="low"),
    SinkPattern("logging.error(",   vuln_class="log_injection", severity="low"),
    SinkPattern("logging.debug(",   vuln_class="log_injection", severity="low"),
    SinkPattern("logger.info(",     vuln_class="log_injection", severity="low"),
    SinkPattern("logger.warning(",  vuln_class="log_injection", severity="low"),
    SinkPattern("logger.error(",    vuln_class="log_injection", severity="low"),
    SinkPattern("print(",           vuln_class="log_injection", severity="info",
                description="print() used as logging → CWE-117"),
]
LOG_SANITIZERS: list[SanitizerPattern] = [
    SanitizerPattern('.replace("\\n", "").replace("\\r", "")',
                     clears_for=["log_injection"], effective_for=["log_injection"],
                     description="Newline stripping — prevents log forging"),
    SanitizerPattern(".replace('\\n', '').replace('\\r', '')",
                     clears_for=["log_injection"], effective_for=["log_injection"]),
    SanitizerPattern("re.sub(r'[\\r\\n]'", clears_for=["log_injection"],
                     effective_for=["log_injection"],
                     description="Regex newline removal"),
]

# CWE-90: LDAP Injection
LDAP_SINKS: list[SinkPattern] = [
    SinkPattern("ldap.search_s(",        vuln_class="ldap_injection", severity="high",
                description="LDAP search_s with user data → CWE-90"),
    SinkPattern(".search_s(",             vuln_class="ldap_injection", severity="high",
                description="LDAP conn.search_s → CWE-90"),
    SinkPattern("ldap.search(",          vuln_class="ldap_injection", severity="high"),
    SinkPattern("ldap3.Connection.search(", vuln_class="ldap_injection", severity="high"),
    SinkPattern(".search(",              vuln_class="ldap_injection", severity="medium",
                description="LDAP search call"),
]
LDAP_SANITIZERS: list[SanitizerPattern] = [
    SanitizerPattern("escape_filter_chars(", clears_for=["ldap_injection"],
                     effective_for=["ldap_injection"],
                     description="ldap.filter.escape_filter_chars() — prevents LDAP injection"),
    SanitizerPattern("ldap.filter.escape_filter_chars(",
                     clears_for=["ldap_injection"], effective_for=["ldap_injection"]),
]

# CWE-611: XML External Entity (XXE)
XXE_SINKS: list[SinkPattern] = [
    SinkPattern("ET.parse(",           vuln_class="xxe", severity="high",
                description="ElementTree parse with external input → CWE-611"),
    SinkPattern("ElementTree.parse(",  vuln_class="xxe", severity="high"),
    SinkPattern("etree.parse(",        vuln_class="xxe", severity="high",
                description="lxml etree.parse → CWE-611"),
    SinkPattern("minidom.parse(",      vuln_class="xxe", severity="high"),
    SinkPattern("xml.sax.parse(",      vuln_class="xxe", severity="high"),
    SinkPattern("parseString(",        vuln_class="xxe", severity="high"),
]
XXE_SANITIZERS: list[SanitizerPattern] = [
    SanitizerPattern("defusedxml.",      clears_for=["xxe"], effective_for=["xxe"],
                     description="defusedxml — safe XML parser"),
    SanitizerPattern("resolve_entities=False", clears_for=["xxe"], effective_for=["xxe"],
                     description="lxml with external entity resolution disabled"),
    SanitizerPattern("XMLParser(resolve_entities=False", clears_for=["xxe"],
                     effective_for=["xxe"]),
]

# Combine into the taint engine's lookup lists
EXTRA_SINKS: list[SinkPattern] = (
    REDIRECT_SINKS + LOG_SINKS + LDAP_SINKS + XXE_SINKS
)
EXTRA_SANITIZERS: list[SanitizerPattern] = (
    REDIRECT_SANITIZERS + LOG_SANITIZERS + LDAP_SANITIZERS + XXE_SANITIZERS
)
