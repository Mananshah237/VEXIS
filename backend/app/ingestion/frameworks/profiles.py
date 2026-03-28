"""Framework-specific taint profiles — additional rules beyond the base lists."""
from __future__ import annotations
from dataclasses import dataclass

from app.ingestion.trust_boundaries import SourcePattern, SinkPattern, SanitizerPattern


@dataclass
class FrameworkProfile:
    name: str
    extra_sources: list[SourcePattern]
    extra_sinks: list[SinkPattern]
    extra_sanitizers: list[SanitizerPattern]


# ─── Flask ───────────────────────────────────────────────────────────────────
FLASK_PROFILE = FrameworkProfile(
    name="flask",
    extra_sources=[
        SourcePattern("request.form.get(",     description="Flask form field"),
        SourcePattern("request.values.get(",   description="Flask values (form+query combined)"),
        SourcePattern("request.files.get(",    description="Flask file upload"),
        SourcePattern("session.get(",          description="Flask session value (user-controlled)"),
        SourcePattern("request.cookies.get(",  description="Flask cookie value"),
        SourcePattern("request.headers.get(",  description="Flask request header"),
        SourcePattern("request.data",          description="Flask raw request body"),
        SourcePattern("request.json",          description="Flask JSON body"),
    ],
    extra_sinks=[
        SinkPattern("render_template_string(", vuln_class="ssti",     severity="high",
                    description="Flask render_template_string — SSTI risk"),
        SinkPattern("make_response(",          vuln_class="xss",      severity="medium",
                    description="Flask make_response can include user data"),
        SinkPattern("redirect(",               vuln_class="ssrf",     severity="medium",
                    description="Flask redirect with user-controlled URL"),
    ],
    extra_sanitizers=[
        # render_template uses Jinja2 auto-escaping — safe for XSS (not SSTI)
        SanitizerPattern("render_template(",   clears_for=["xss"], effective_for=["xss"],
                         description="Flask render_template uses auto-escaping"),
    ],
)

# ─── Django ──────────────────────────────────────────────────────────────────
DJANGO_PROFILE = FrameworkProfile(
    name="django",
    extra_sources=[
        SourcePattern("request.GET.get(",    description="Django GET parameter"),
        SourcePattern("request.POST.get(",   description="Django POST field"),
        SourcePattern("request.FILES.get(",  description="Django uploaded file"),
        SourcePattern("request.META.get(",   description="Django request meta (headers)"),
        SourcePattern("request.data.get(",   description="Django REST framework request data"),
        SourcePattern("kwargs.get(",         description="Django URL kwargs (URL params)"),
        SourcePattern("self.kwargs.get(",    description="Django class-based view URL kwargs"),
    ],
    extra_sinks=[
        SinkPattern("mark_safe(",    vuln_class="xss",  severity="high",
                    description="Django mark_safe — marks string as safe HTML, XSS if user data"),
        SinkPattern("format_html(", vuln_class="xss",  severity="medium",
                    description="Django format_html without proper escaping"),
        SinkPattern(".raw(",        vuln_class="sqli",  severity="high",
                    description="Django ORM raw() query — SQLi risk"),
        SinkPattern(".extra(",      vuln_class="sqli",  severity="high",
                    description="Django ORM extra() — can include raw SQL"),
    ],
    extra_sanitizers=[
        # Django ORM parameterized methods
        SanitizerPattern(".filter(",    clears_for=["sqli"], effective_for=["sqli"],
                         description="Django ORM filter() — parameterized"),
        SanitizerPattern(".get(",       clears_for=["sqli"], effective_for=["sqli"],
                         description="Django ORM get() — parameterized"),
        SanitizerPattern(".exclude(",   clears_for=["sqli"], effective_for=["sqli"],
                         description="Django ORM exclude() — parameterized"),
        SanitizerPattern("escape(",     clears_for=["xss"], effective_for=["xss"],
                         description="Django escape() — HTML encoding"),
        SanitizerPattern("conditional_escape(", clears_for=["xss"], effective_for=["xss"],
                         description="Django conditional_escape()"),
    ],
)

# ─── FastAPI ─────────────────────────────────────────────────────────────────
FASTAPI_PROFILE = FrameworkProfile(
    name="fastapi",
    extra_sources=[
        SourcePattern("Request.query_params.get(", description="FastAPI query param"),
        SourcePattern("request.query_params.get(", description="FastAPI query param"),
        SourcePattern("request.form()",            description="FastAPI form data"),
        SourcePattern("request.body()",            description="FastAPI raw body"),
        SourcePattern("request.headers.get(",      description="FastAPI request header"),
        SourcePattern("request.cookies.get(",      description="FastAPI cookie"),
    ],
    extra_sinks=[
        SinkPattern("HTMLResponse(",  vuln_class="xss",  severity="medium",
                    description="FastAPI HTMLResponse with user data"),
    ],
    extra_sanitizers=[
        # FastAPI's JSONResponse automatically serializes — safe from XSS
        SanitizerPattern("JSONResponse(", clears_for=["xss"], effective_for=["xss"],
                         description="FastAPI JSONResponse — JSON-encodes content"),
    ],
)

# ─── Express (JS) ────────────────────────────────────────────────────────────
EXPRESS_PROFILE = FrameworkProfile(
    name="express",
    extra_sources=[
        SourcePattern("req.query.",    description="Express query string param"),
        SourcePattern("req.body.",     description="Express request body field"),
        SourcePattern("req.params.",   description="Express URL parameter"),
        SourcePattern("req.headers[", description="Express request header"),
        SourcePattern("req.cookies.", description="Express cookie value"),
        SourcePattern("req.query[",   description="Express query bracket notation"),
    ],
    extra_sinks=[
        SinkPattern("res.send(",    vuln_class="xss",  severity="medium",
                    description="Express res.send with user data — XSS risk"),
        SinkPattern("res.render(", vuln_class="ssti",  severity="high",
                    description="Express res.render — SSTI if template engine vulnerable"),
        SinkPattern("res.end(",    vuln_class="xss",   severity="medium",
                    description="Express res.end with user data"),
    ],
    extra_sanitizers=[
        SanitizerPattern("res.json(", clears_for=["xss"], effective_for=["xss"],
                         description="Express res.json — JSON-encodes, safe for XSS"),
    ],
)

_PROFILE_MAP: dict[str, FrameworkProfile] = {
    "flask":   FLASK_PROFILE,
    "django":  DJANGO_PROFILE,
    "fastapi": FASTAPI_PROFILE,
    "express": EXPRESS_PROFILE,
}


def get_framework_profile(framework: str | None) -> FrameworkProfile | None:
    if framework is None:
        return None
    return _PROFILE_MAP.get(framework)
