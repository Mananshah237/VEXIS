"""
Trust boundary definitions — sources, sinks, and sanitizers for Python.
CCSM: sanitizers carry a continuous constraint_power (0.0–1.0) instead of
a boolean is_partial flag.  constraint_power is applied multiplicatively when
propagating taint: new_danger = current_danger * (1.0 - constraint_power).
A path whose effective danger drops below DANGER_THRESHOLD is suppressed.
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
    constraint_power: float = 0.0  # 0.0=no constraint, 1.0=full elimination
    description: str = ""
    effective_for: list[str] = field(default_factory=list)  # vuln_classes this actually protects

    @property
    def is_partial(self) -> bool:
        """Backward-compat: any sanitizer with constraint_power < 0.95 is 'partial'."""
        return self.constraint_power < 0.95


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
    # SQLi sanitizers — parameterized queries (constraint_power=0.99)
    SanitizerPattern('?", (', clears_for=["sqli"], constraint_power=0.99,
                     effective_for=["sqli"], description="SQLite ? placeholder with tuple params (double quotes)"),
    SanitizerPattern("?', (", clears_for=["sqli"], constraint_power=0.99,
                     effective_for=["sqli"], description="SQLite ? placeholder with tuple params (single quotes)"),
    SanitizerPattern('?", [', clears_for=["sqli"], constraint_power=0.99,
                     effective_for=["sqli"], description="SQLite ? placeholder with list params"),
    SanitizerPattern('%s", (', clears_for=["sqli"], constraint_power=0.99,
                     effective_for=["sqli"], description="DB-API %s placeholder with tuple params"),
    SanitizerPattern("%s', (", clears_for=["sqli"], constraint_power=0.99,
                     effective_for=["sqli"], description="DB-API %s placeholder with tuple params"),
    SanitizerPattern('execute(%s,', clears_for=["sqli"], constraint_power=0.99,
                     effective_for=["sqli"], description="DB-API %s direct"),
    SanitizerPattern("execute(%s,", clears_for=["sqli"], constraint_power=0.99,
                     effective_for=["sqli"], description="DB-API %s direct"),
    SanitizerPattern(".filter(", clears_for=["sqli"], constraint_power=0.99,
                     effective_for=["sqli"], description="ORM filter (parameterized)"),
    SanitizerPattern(".filter_by(", clears_for=["sqli"], constraint_power=0.99,
                     effective_for=["sqli"], description="ORM filter_by"),

    # CMDi sanitizers
    SanitizerPattern("shlex.quote(", clears_for=["cmdi"], constraint_power=0.90,
                     effective_for=["cmdi"], description="Shell quoting"),
    SanitizerPattern("shlex.split(", clears_for=["cmdi"], constraint_power=0.75,
                     effective_for=["cmdi"], description="Shell split (safer than string concat)"),

    # Path traversal sanitizers
    SanitizerPattern(
        "os.path.realpath(",
        clears_for=[],
        constraint_power=0.50,
        effective_for=["path_traversal"],
        description="Resolves symlinks but still needs startswith(SAFE_DIR) prefix check",
    ),
    SanitizerPattern("os.path.abspath(", clears_for=[], constraint_power=0.40,
                     effective_for=["path_traversal"],
                     description="Normalizes path but needs prefix check to be safe"),

    # XSS sanitizers — ONLY protect against XSS
    SanitizerPattern("html.escape(", clears_for=["xss"], constraint_power=0.90,
                     effective_for=["xss"], description="HTML escaping (XSS only)"),
    SanitizerPattern("markupsafe.escape(", clears_for=["xss"], constraint_power=0.90,
                     effective_for=["xss"], description="Markupsafe escape (XSS only)"),
    SanitizerPattern("escape(", clears_for=["xss"], constraint_power=0.90,
                     effective_for=["xss"], description="Generic escape function (XSS only)"),
    SanitizerPattern("bleach.clean(", clears_for=["xss"], constraint_power=0.85,
                     effective_for=["xss"], description="Bleach HTML sanitizer (XSS only)"),
    SanitizerPattern("DOMPurify.sanitize(", clears_for=["xss"], constraint_power=0.90,
                     effective_for=["xss"], description="DOMPurify (XSS only)"),

    # Deserialization sanitizers
    SanitizerPattern("yaml.safe_load(", clears_for=["deserialization"], constraint_power=0.95,
                     effective_for=["deserialization"], description="Safe YAML loading"),
    SanitizerPattern("SafeLoader", clears_for=["deserialization"], constraint_power=0.95,
                     effective_for=["deserialization"], description="YAML SafeLoader"),

    # SSRF sanitizers
    SanitizerPattern("urlparse(", clears_for=[], constraint_power=0.30,
                     effective_for=["ssrf", "open_redirect"],
                     description="URL parsing (partial — needs allowlist check)"),
    SanitizerPattern(".hostname", clears_for=[], constraint_power=0.20,
                     effective_for=["ssrf"], description="Hostname extraction (partial)"),
    SanitizerPattern("urllib.parse.quote(", clears_for=[], constraint_power=0.10,
                     effective_for=["ssrf"], description="URL encoding (partial — does not restrict destination)"),

    # SSTI sanitizers
    SanitizerPattern("SandboxedEnvironment", clears_for=["ssti"], constraint_power=0.95,
                     effective_for=["ssti"], description="Jinja2 sandboxed environment"),

    # Weak string manipulation — low constraint, easily bypassed
    # Listed AFTER more specific patterns so specific matches win
    SanitizerPattern("re.match(", clears_for=[], constraint_power=0.70,
                     effective_for=["sqli", "cmdi", "path_traversal"],
                     description="Regex match — constraining if pattern is strict"),
    SanitizerPattern("re.sub(", clears_for=[], constraint_power=0.50,
                     effective_for=["sqli", "cmdi", "log_injection"],
                     description="Regex substitution — partial constraint"),
    SanitizerPattern(".replace(", clears_for=[], constraint_power=0.15,
                     effective_for=["sqli", "log_injection"],
                     description="String replace — single-pass, trivially bypassed"),
    SanitizerPattern(".strip(", clears_for=[], constraint_power=0.05,
                     effective_for=["log_injection"],
                     description="Strip whitespace — near-zero security constraint"),

    # Numeric type casting — effective for ALL injection types (output is non-injectable)
    SanitizerPattern("int(", clears_for=["sqli", "cmdi", "path_traversal", "ssrf", "ssti", "xss"],
                     constraint_power=0.95,
                     effective_for=["sqli", "cmdi", "path_traversal", "ssrf", "ssti", "xss"],
                     description="Integer cast — output is always numeric, cannot be injected"),
    SanitizerPattern("float(", clears_for=["sqli", "cmdi", "path_traversal", "ssrf", "ssti", "xss"],
                     constraint_power=0.95,
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
    # SQLi — parameterized queries (more specific patterns first)
    SanitizerPattern("query('", clears_for=["sqli"], constraint_power=0.99,
                     effective_for=["sqli"],
                     description="JS query() with single-quoted string first arg = parameterized"),
    SanitizerPattern('query("', clears_for=["sqli"], constraint_power=0.99,
                     effective_for=["sqli"],
                     description="JS query() with double-quoted string first arg = parameterized"),
    SanitizerPattern("?, [", clears_for=["sqli"], constraint_power=0.90,
                     effective_for=["sqli"], description="MySQL ? placeholder fallback"),
    SanitizerPattern('db.query("', clears_for=["sqli"], constraint_power=0.99,
                     effective_for=["sqli"], description="Literal SQL string (no template)"),
    SanitizerPattern(".where(", clears_for=["sqli"], constraint_power=0.95,
                     effective_for=["sqli"], description="Knex/Sequelize where clause"),
    # CMDi
    SanitizerPattern("execFile(", clears_for=["cmdi", "xss"], constraint_power=0.90,
                     effective_for=["cmdi", "xss"],
                     description="execFile: no shell, stdout not directly user-controlled HTML"),
    SanitizerPattern("shell-escape", clears_for=["cmdi"], constraint_power=0.90,
                     effective_for=["cmdi"]),
    SanitizerPattern("shellEscape(", clears_for=["cmdi"], constraint_power=0.90,
                     effective_for=["cmdi"]),
    # XSS
    SanitizerPattern("DOMPurify.sanitize(", clears_for=["xss"], constraint_power=0.90,
                     effective_for=["xss"]),
    SanitizerPattern("escape-html", clears_for=["xss"], constraint_power=0.90,
                     effective_for=["xss"]),
    SanitizerPattern("he.encode(", clears_for=["xss"], constraint_power=0.90,
                     effective_for=["xss"]),
    SanitizerPattern("escapeHtml(", clears_for=["xss"], constraint_power=0.90,
                     effective_for=["xss"]),
    # Path traversal
    SanitizerPattern("path.resolve(", clears_for=[], constraint_power=0.45,
                     effective_for=["path_traversal"],
                     description="path.resolve() — needs startsWith check to be effective"),
    SanitizerPattern(".startsWith(", clears_for=[], constraint_power=0.40,
                     effective_for=["path_traversal"],
                     description="startsWith check — needs path.resolve() too"),
    # SSRF
    SanitizerPattern("new URL(", clears_for=[], constraint_power=0.30,
                     effective_for=["ssrf"],
                     description="URL parsing — needs allowlist check"),
    SanitizerPattern(".hostname", clears_for=[], constraint_power=0.20,
                     effective_for=["ssrf"]),
    # Numeric type casting
    SanitizerPattern("parseInt(", clears_for=["sqli", "cmdi", "path_traversal", "ssrf", "ssti", "xss"],
                     constraint_power=0.95,
                     effective_for=["sqli", "cmdi", "path_traversal", "ssrf", "ssti", "xss"],
                     description="parseInt — numeric output is safe"),
    SanitizerPattern("parseFloat(", clears_for=["sqli", "cmdi", "path_traversal", "ssrf", "ssti", "xss"],
                     constraint_power=0.95,
                     effective_for=["sqli", "cmdi", "path_traversal", "ssrf", "ssti", "xss"],
                     description="parseFloat — numeric output is safe"),
    SanitizerPattern("Number(", clears_for=["sqli", "cmdi", "path_traversal", "ssrf", "ssti", "xss"],
                     constraint_power=0.95,
                     effective_for=["sqli", "cmdi", "path_traversal", "ssrf", "ssti", "xss"],
                     description="Number() cast — numeric output is safe"),
]


# ─── Java ───────────────────────────────────────────────────────────────────

JAVA_TAINT_SOURCES: list[SourcePattern] = [
    # Servlet / JSP
    SourcePattern("request.getParameter(", source_type="http_param", description="Servlet request param"),
    SourcePattern("request.getParameterValues(", source_type="http_param", description="Servlet multi-value param"),
    SourcePattern("getParameter(", source_type="http_param", description="Servlet param (any handle)"),
    SourcePattern("request.getHeader(", source_type="http_header", description="Servlet header"),
    SourcePattern("request.getQueryString(", source_type="http_param", description="Servlet query string"),
    SourcePattern("request.getCookies(", source_type="http_cookie", description="Servlet cookies"),
    SourcePattern("getInputStream(", source_type="http_body", description="Servlet request body"),
    # Spring MVC binding annotations
    SourcePattern("@RequestParam", source_type="http_param", description="Spring request param"),
    SourcePattern("@PathVariable", source_type="http_param", description="Spring path variable"),
    SourcePattern("@RequestBody", source_type="http_body", description="Spring request body"),
    SourcePattern("@RequestHeader", source_type="http_header", description="Spring header"),
    # Process / env
    SourcePattern("System.getenv(", source_type="env_var", description="Environment variable"),
]

JAVA_TAINT_SINKS: list[SinkPattern] = [
    # SQL Injection
    SinkPattern("executeQuery(", vuln_class="sqli", severity="critical", description="JDBC Statement.executeQuery"),
    SinkPattern("executeUpdate(", vuln_class="sqli", severity="critical", description="JDBC Statement.executeUpdate"),
    SinkPattern("executeLargeUpdate(", vuln_class="sqli", severity="critical"),
    SinkPattern("createQuery(", vuln_class="sqli", severity="high", description="JPA/Hibernate HQL injection"),
    SinkPattern("createNativeQuery(", vuln_class="sqli", severity="high"),
    # Command Injection
    SinkPattern(".exec(", vuln_class="cmdi", severity="critical", description="Runtime.exec"),
    SinkPattern("getRuntime().exec(", vuln_class="cmdi", severity="critical"),
    SinkPattern("ProcessBuilder(", vuln_class="cmdi", severity="critical", description="ProcessBuilder command"),
    # Path Traversal
    SinkPattern("new File(", vuln_class="path_traversal", severity="high", description="File construction with user input"),
    SinkPattern("new FileInputStream(", vuln_class="path_traversal", severity="high"),
    SinkPattern("new FileReader(", vuln_class="path_traversal", severity="high"),
    SinkPattern("new FileOutputStream(", vuln_class="path_traversal", severity="high"),
    SinkPattern("Files.readAllBytes(", vuln_class="path_traversal", severity="high"),
    SinkPattern("Files.newInputStream(", vuln_class="path_traversal", severity="high"),
    SinkPattern("Files.lines(", vuln_class="path_traversal", severity="high"),
    # Cross-Site Scripting (reflected, servlet response)
    SinkPattern("getWriter().print", vuln_class="xss", severity="high", description="Servlet response writer"),
    SinkPattern("getWriter().write", vuln_class="xss", severity="high"),
    # SSRF
    SinkPattern(".openConnection(", vuln_class="ssrf", severity="high", description="URL.openConnection with user URL"),
    SinkPattern(".openStream(", vuln_class="ssrf", severity="high"),
    # Insecure Deserialization
    SinkPattern("readObject(", vuln_class="deserialization", severity="critical", description="Java native deserialization"),
    SinkPattern("new ObjectInputStream(", vuln_class="deserialization", severity="high"),
]

JAVA_SANITIZERS: list[SanitizerPattern] = [
    # Numeric casts — output is non-injectable, effective for all injection classes
    SanitizerPattern("Integer.parseInt(", clears_for=["sqli", "cmdi", "path_traversal", "ssrf", "xss"],
                     constraint_power=0.95,
                     effective_for=["sqli", "cmdi", "path_traversal", "ssrf", "xss"],
                     description="Integer parse — numeric output cannot be injected"),
    SanitizerPattern("Long.parseLong(", clears_for=["sqli", "cmdi", "path_traversal", "ssrf", "xss"],
                     constraint_power=0.95,
                     effective_for=["sqli", "cmdi", "path_traversal", "ssrf", "xss"],
                     description="Long parse — numeric output"),
    SanitizerPattern("Double.parseDouble(", clears_for=["sqli", "cmdi", "path_traversal", "ssrf", "xss"],
                     constraint_power=0.95,
                     effective_for=["sqli", "cmdi", "path_traversal", "ssrf", "xss"],
                     description="Double parse — numeric output"),
    # SQLi — parameterized queries
    SanitizerPattern("prepareStatement(", clears_for=["sqli"], constraint_power=0.90,
                     effective_for=["sqli"], description="JDBC PreparedStatement (parameterized)"),
    SanitizerPattern("setString(", clears_for=["sqli"], constraint_power=0.85,
                     effective_for=["sqli"], description="PreparedStatement parameter binding"),
    # Path traversal
    SanitizerPattern("FilenameUtils.getName(", clears_for=["path_traversal"], constraint_power=0.90,
                     effective_for=["path_traversal"],
                     description="Apache Commons FilenameUtils.getName — strips directory components"),
    SanitizerPattern(".getCanonicalPath(", clears_for=[], constraint_power=0.55,
                     effective_for=["path_traversal"],
                     description="Canonical path — partial, needs a prefix check"),
    SanitizerPattern(".normalize(", clears_for=[], constraint_power=0.45,
                     effective_for=["path_traversal"],
                     description="Path normalize — partial, needs a prefix check"),
    # XSS
    SanitizerPattern("encodeForHTML(", clears_for=["xss"], constraint_power=0.90,
                     effective_for=["xss"], description="OWASP ESAPI HTML encoder"),
    SanitizerPattern("StringEscapeUtils.escapeHtml", clears_for=["xss"], constraint_power=0.90,
                     effective_for=["xss"], description="Apache Commons HTML escaping"),
    SanitizerPattern("HtmlUtils.htmlEscape(", clears_for=["xss"], constraint_power=0.90,
                     effective_for=["xss"], description="Spring HtmlUtils escaping"),
]


# ─── Go ───────────────────────────────────────────────────────────────────

GO_TAINT_SOURCES: list[SourcePattern] = [
    SourcePattern("FormValue(", source_type="http_param", description="net/http FormValue"),
    SourcePattern(".Query().Get(", source_type="http_param", description="URL query param"),
    SourcePattern("Header.Get(", source_type="http_header", description="HTTP header"),
    SourcePattern("mux.Vars(", source_type="http_param", description="gorilla/mux path vars"),
    SourcePattern("c.Query(", source_type="http_param", description="Gin query param"),
    SourcePattern("c.Param(", source_type="http_param", description="Gin path param"),
    SourcePattern("c.PostForm(", source_type="http_param", description="Gin form value"),
    SourcePattern("os.Getenv(", source_type="env_var", description="Environment variable"),
]
GO_TAINT_SINKS: list[SinkPattern] = [
    SinkPattern("db.Query(", vuln_class="sqli", severity="critical", description="database/sql Query"),
    SinkPattern("db.Exec(", vuln_class="sqli", severity="critical"),
    SinkPattern(".QueryRow(", vuln_class="sqli", severity="high"),
    SinkPattern("exec.Command(", vuln_class="cmdi", severity="critical", description="os/exec Command"),
    SinkPattern("os.Open(", vuln_class="path_traversal", severity="high"),
    SinkPattern("os.ReadFile(", vuln_class="path_traversal", severity="high"),
    SinkPattern("ioutil.ReadFile(", vuln_class="path_traversal", severity="high"),
    SinkPattern("http.Get(", vuln_class="ssrf", severity="high"),
    SinkPattern("http.NewRequest(", vuln_class="ssrf", severity="high"),
]
GO_SANITIZERS: list[SanitizerPattern] = [
    SanitizerPattern("strconv.Atoi(", clears_for=["sqli", "cmdi", "path_traversal", "ssrf", "xss"],
                     constraint_power=0.95,
                     effective_for=["sqli", "cmdi", "path_traversal", "ssrf", "xss"],
                     description="Atoi — numeric output"),
    SanitizerPattern("strconv.ParseInt(", clears_for=["sqli", "cmdi", "path_traversal", "ssrf", "xss"],
                     constraint_power=0.95,
                     effective_for=["sqli", "cmdi", "path_traversal", "ssrf", "xss"],
                     description="ParseInt — numeric output"),
    SanitizerPattern("filepath.Base(", clears_for=["path_traversal"], constraint_power=0.90,
                     effective_for=["path_traversal"], description="filepath.Base — strips directory"),
    SanitizerPattern("template.HTMLEscapeString(", clears_for=["xss"], constraint_power=0.90,
                     effective_for=["xss"], description="HTML escaping"),
]


# ─── Ruby ─────────────────────────────────────────────────────────────────

RUBY_TAINT_SOURCES: list[SourcePattern] = [
    SourcePattern("params[", source_type="http_param", description="Rails params"),
    SourcePattern("params.require(", source_type="http_param", description="Rails strong params"),
    SourcePattern("cookies[", source_type="http_cookie", description="Rails cookies"),
    SourcePattern("request.headers[", source_type="http_header", description="Rails headers"),
    SourcePattern("ENV[", source_type="env_var", description="Environment variable"),
]
RUBY_TAINT_SINKS: list[SinkPattern] = [
    SinkPattern("connection.execute(", vuln_class="sqli", severity="critical", description="ActiveRecord raw SQL"),
    SinkPattern("find_by_sql(", vuln_class="sqli", severity="critical"),
    SinkPattern("system(", vuln_class="cmdi", severity="critical", description="Kernel#system"),
    SinkPattern("IO.popen(", vuln_class="cmdi", severity="critical"),
    SinkPattern("File.open(", vuln_class="path_traversal", severity="high"),
    SinkPattern("File.read(", vuln_class="path_traversal", severity="high"),
    SinkPattern("send_file(", vuln_class="path_traversal", severity="high"),
    SinkPattern("Net::HTTP.get(", vuln_class="ssrf", severity="high"),
]
RUBY_SANITIZERS: list[SanitizerPattern] = [
    SanitizerPattern(".to_i", clears_for=["sqli", "cmdi", "path_traversal", "ssrf", "xss"],
                     constraint_power=0.95,
                     effective_for=["sqli", "cmdi", "path_traversal", "ssrf", "xss"],
                     description="to_i — numeric coercion"),
    SanitizerPattern("Integer(", clears_for=["sqli", "cmdi", "path_traversal", "ssrf", "xss"],
                     constraint_power=0.90,
                     effective_for=["sqli", "cmdi", "path_traversal", "ssrf", "xss"],
                     description="Integer() — strict numeric coercion"),
    SanitizerPattern("ERB::Util.html_escape(", clears_for=["xss"], constraint_power=0.90,
                     effective_for=["xss"], description="ERB HTML escaping"),
    SanitizerPattern("File.basename(", clears_for=["path_traversal"], constraint_power=0.90,
                     effective_for=["path_traversal"], description="File.basename — strips directory"),
]


# ─── C / C++ ──────────────────────────────────────────────────────────────

C_TAINT_SOURCES: list[SourcePattern] = [
    SourcePattern("getenv(", source_type="env_var", description="Environment variable"),
    SourcePattern("scanf(", source_type="user_input", description="stdin scanf"),
    SourcePattern("fgets(", source_type="user_input", description="stdin fgets"),
    SourcePattern("gets(", source_type="user_input", description="stdin gets (unsafe)"),
    SourcePattern("recv(", source_type="http_body", description="socket recv"),
    SourcePattern("req.get(", source_type="http_param", description="C++ web framework param"),
]
C_TAINT_SINKS: list[SinkPattern] = [
    # Command injection
    SinkPattern("system(", vuln_class="cmdi", severity="critical", description="system() shell"),
    SinkPattern("popen(", vuln_class="cmdi", severity="critical"),
    SinkPattern("execlp(", vuln_class="cmdi", severity="critical"),
    SinkPattern("execvp(", vuln_class="cmdi", severity="critical"),
    # Buffer overflow (CWE-120/787)
    SinkPattern("strcpy(", vuln_class="buffer_overflow", severity="high", description="Unbounded string copy"),
    SinkPattern("strcat(", vuln_class="buffer_overflow", severity="high"),
    SinkPattern("sprintf(", vuln_class="buffer_overflow", severity="high"),
    SinkPattern("gets(", vuln_class="buffer_overflow", severity="critical", description="gets() — never safe"),
    SinkPattern("memcpy(", vuln_class="buffer_overflow", severity="medium"),
    # Path traversal
    SinkPattern("fopen(", vuln_class="path_traversal", severity="high"),
    # SQL injection (C/C++ DB APIs)
    SinkPattern("mysql_query(", vuln_class="sqli", severity="critical"),
    SinkPattern("PQexec(", vuln_class="sqli", severity="critical"),
    SinkPattern("sqlite3_exec(", vuln_class="sqli", severity="critical"),
    SinkPattern("->query(", vuln_class="sqli", severity="high", description="C++ DB query method"),
]
C_SANITIZERS: list[SanitizerPattern] = [
    SanitizerPattern("atoi(", clears_for=["sqli", "cmdi", "path_traversal", "buffer_overflow"],
                     constraint_power=0.90,
                     effective_for=["sqli", "cmdi", "path_traversal", "buffer_overflow"],
                     description="atoi — numeric output"),
    SanitizerPattern("strtol(", clears_for=["sqli", "cmdi", "path_traversal", "buffer_overflow"],
                     constraint_power=0.90,
                     effective_for=["sqli", "cmdi", "path_traversal", "buffer_overflow"],
                     description="strtol — numeric output"),
    SanitizerPattern("snprintf(", clears_for=["buffer_overflow"], constraint_power=0.75,
                     effective_for=["buffer_overflow"], description="snprintf — bounded write"),
    SanitizerPattern("strncpy(", clears_for=["buffer_overflow"], constraint_power=0.60,
                     effective_for=["buffer_overflow"], description="strncpy — bounded (still needs null-term)"),
]


# ─── Rust ─────────────────────────────────────────────────────────────────

RUST_TAINT_SOURCES: list[SourcePattern] = [
    SourcePattern(".param(", source_type="http_param", description="Web framework path param"),
    SourcePattern("req.query(", source_type="http_param", description="Query param"),
    SourcePattern("std::env::var(", source_type="env_var", description="Environment variable"),
    SourcePattern("env::var(", source_type="env_var", description="Environment variable"),
]
RUST_TAINT_SINKS: list[SinkPattern] = [
    SinkPattern("Command::new(", vuln_class="cmdi", severity="critical", description="std::process::Command"),
    SinkPattern("sqlx::query(", vuln_class="sqli", severity="high"),
    SinkPattern("diesel::sql_query(", vuln_class="sqli", severity="high"),
    SinkPattern("File::open(", vuln_class="path_traversal", severity="high"),
    SinkPattern("fs::read(", vuln_class="path_traversal", severity="high"),
    SinkPattern("fs::read_to_string(", vuln_class="path_traversal", severity="high"),
    SinkPattern("reqwest::get(", vuln_class="ssrf", severity="high"),
]
RUST_SANITIZERS: list[SanitizerPattern] = [
    SanitizerPattern("parse::<", clears_for=["sqli", "cmdi", "path_traversal", "ssrf"],
                     constraint_power=0.95,
                     effective_for=["sqli", "cmdi", "path_traversal", "ssrf"],
                     description="typed parse (e.g. parse::<i32>) — numeric output"),
]


# ─── Bash ─────────────────────────────────────────────────────────────────

BASH_TAINT_SOURCES: list[SourcePattern] = [
    SourcePattern("$1", source_type="cli_arg", description="Positional parameter"),
    SourcePattern("$2", source_type="cli_arg", description="Positional parameter"),
    SourcePattern("$QUERY_STRING", source_type="http_param", description="CGI query string"),
    SourcePattern("read ", source_type="user_input", description="read builtin"),
]
BASH_TAINT_SINKS: list[SinkPattern] = [
    SinkPattern("eval ", vuln_class="cmdi", severity="critical", description="eval of untrusted input"),
    SinkPattern("bash -c", vuln_class="cmdi", severity="critical"),
    SinkPattern("sh -c", vuln_class="cmdi", severity="critical"),
]
BASH_SANITIZERS: list[SanitizerPattern] = [
    SanitizerPattern("declare -i", clears_for=["cmdi"], constraint_power=0.85,
                     effective_for=["cmdi"], description="integer-typed variable"),
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
    SanitizerPattern(".startswith('/')", clears_for=["open_redirect"], constraint_power=0.85,
                     effective_for=["open_redirect"],
                     description="Relative URL check — prevents off-site redirect"),
    SanitizerPattern('.startswith("/")', clears_for=["open_redirect"], constraint_power=0.85,
                     effective_for=["open_redirect"]),
    SanitizerPattern("urlparse(", clears_for=[], constraint_power=0.30,
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
    # Specific newline-stripping patterns (high constraint — listed before generic re.sub)
    SanitizerPattern('.replace("\\n", "").replace("\\r", "")',
                     clears_for=["log_injection"], constraint_power=0.85,
                     effective_for=["log_injection"],
                     description="Newline stripping — prevents log forging"),
    SanitizerPattern(".replace('\\n', '').replace('\\r', '')",
                     clears_for=["log_injection"], constraint_power=0.85,
                     effective_for=["log_injection"]),
    SanitizerPattern("re.sub(r'[\\r\\n]'", clears_for=["log_injection"], constraint_power=0.85,
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
    SanitizerPattern("escape_filter_chars(", clears_for=["ldap_injection"], constraint_power=0.90,
                     effective_for=["ldap_injection"],
                     description="ldap.filter.escape_filter_chars() — prevents LDAP injection"),
    SanitizerPattern("ldap.filter.escape_filter_chars(",
                     clears_for=["ldap_injection"], constraint_power=0.90,
                     effective_for=["ldap_injection"]),
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
    SanitizerPattern("defusedxml.",      clears_for=["xxe"], constraint_power=0.95,
                     effective_for=["xxe"],
                     description="defusedxml — safe XML parser"),
    SanitizerPattern("resolve_entities=False", clears_for=["xxe"], constraint_power=0.90,
                     effective_for=["xxe"],
                     description="lxml with external entity resolution disabled"),
    SanitizerPattern("XMLParser(resolve_entities=False", clears_for=["xxe"], constraint_power=0.95,
                     effective_for=["xxe"]),
]

# Combine into the taint engine's lookup lists
EXTRA_SINKS: list[SinkPattern] = (
    REDIRECT_SINKS + LOG_SINKS + LDAP_SINKS + XXE_SINKS
)
EXTRA_SANITIZERS: list[SanitizerPattern] = (
    REDIRECT_SANITIZERS + LOG_SANITIZERS + LDAP_SANITIZERS + XXE_SANITIZERS
)
