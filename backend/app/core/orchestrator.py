"""
Scan orchestrator — coordinates the full analysis pipeline.
Called as a FastAPI BackgroundTask.

Supports two analysis modes:
  - Single-file: one .py file, intra-file taint only (fast)
  - Multi-file / project: all .py files in directory, cross-file taint tracking

Multi-file raw_code: if the submitted code contains markers of the form
    # === FILE: filename.py ===
it is split into separate temp files and analysed as a project.

Hardening (Sprint 3):
  - asyncio.wait_for timeout (scan_timeout_seconds from settings, default 600)
  - LLM call budget (max_llm_calls_per_scan, default 100)
  - Large file skip (>10,000 lines)
  - Per-file error isolation (one bad file does not abort the scan)
"""
import asyncio
import tempfile
import os
import re
from datetime import datetime
from pathlib import Path
import structlog

from app.database import AsyncSessionLocal
from app.models.scan import Scan, ScanStatus
from sqlalchemy import select
import uuid

log = structlog.get_logger()

# Marker that separates files in a multi-file raw_code submission
_FILE_MARKER_RE = re.compile(r'^#\s*={3,}\s*FILE:\s*(.+?)\s*={3,}\s*$', re.MULTILINE)

# Lines-per-file limit — files larger than this are skipped with a warning
_MAX_FILE_LINES = 10_000


async def _broadcast(scan_id: str, phase: str, progress: float, message: str) -> None:
    import json
    payload = {"phase": phase, "progress": progress, "message": message}

    # In-process WebSocket manager (works when scan runs in API process)
    try:
        from app.api.ws.scan_ws import manager
        await manager.broadcast(scan_id, payload)
    except Exception as e:
        log.debug("ws.broadcast_failed", error=str(e))

    # Redis pubsub (works cross-process for Celery workers)
    try:
        import redis.asyncio as aioredis
        import os as _os
        redis_url = _os.environ.get("REDIS_URL", "redis://localhost:6379/0")
        r = aioredis.from_url(redis_url)
        await r.publish(f"scan:{scan_id}:progress", json.dumps(payload))
        await r.aclose()
    except Exception as e:
        log.debug("redis.publish_failed", error=str(e))


async def run_scan(scan_id: str) -> None:
    """Entry point — wraps the scan in a global timeout."""
    from app.config import settings
    try:
        await asyncio.wait_for(
            _run_scan_impl(scan_id),
            timeout=float(settings.scan_timeout_seconds),
        )
    except asyncio.TimeoutError:
        log.error("scan.timeout", scan_id=scan_id, timeout=settings.scan_timeout_seconds)
        async with AsyncSessionLocal() as db:
            result = await db.execute(select(Scan).where(Scan.id == uuid.UUID(scan_id)))
            scan = result.scalar_one_or_none()
            if scan:
                scan.status = "timeout"
                scan.error_message = (
                    f"Scan exceeded timeout of {settings.scan_timeout_seconds}s. "
                    "Partial results (if any) were saved."
                )
                scan.completed_at = datetime.utcnow()
                await db.commit()
        await _broadcast(
            scan_id, "failed", 0.0,
            f"Scan timed out after {settings.scan_timeout_seconds}s"
        )


async def _run_scan_impl(scan_id: str) -> None:
    log.info("scan.start", scan_id=scan_id)
    _temp_dir: str | None = None

    from app.config import settings
    from app.reasoning.budget import LLMBudget
    budget = LLMBudget(max_calls=settings.max_llm_calls_per_scan)

    async with AsyncSessionLocal() as db:
        result = await db.execute(select(Scan).where(Scan.id == uuid.UUID(scan_id)))
        scan = result.scalar_one_or_none()
        if not scan:
            log.error("scan.not_found", scan_id=scan_id)
            return

        try:
            scan.started_at = datetime.utcnow()
            await _update_status(db, scan, ScanStatus.PARSING, 0.05)
            await _broadcast(scan_id, "parsing", 0.1, "Fetching source code...")

            source_path = await _fetch_source(scan)
            if scan.source_type == "raw_code":
                _temp_dir = source_path

            # Snapshot source code to MinIO (non-blocking; failure does not abort scan)
            try:
                from app.core.storage import upload_code_snapshot
                _snapshot_source = scan.source_ref[:10_000]  # first 10KB for inline code
                await upload_code_snapshot(str(scan_id), _snapshot_source)
            except Exception:
                pass

            _JS_EXTENSIONS = {"*.js", "*.jsx", "*.ts", "*.tsx"}
            all_py_files = sorted(
                f for ext in ["*.py", "*.js", "*.jsx", "*.ts", "*.tsx"]
                for f in Path(source_path).rglob(ext)
            )

            # ── Vendored / minified / generated file exclusion ────────────────
            # Normalise source_path to forward slashes for consistent matching
            _src_prefix = source_path.replace("\\", "/").rstrip("/") + "/"
            _excl_paths = [p.lower() for p in settings.excluded_path_patterns]
            _excl_names = [n.lower() for n in settings.excluded_filename_patterns]

            def _is_excluded(f: Path) -> str | None:
                """Return exclusion reason string, or None if file should be kept."""
                norm = f.as_posix().replace(_src_prefix, "/").lower()
                for pat in _excl_paths:
                    if pat in norm:
                        return "vendor"
                name = f.name.lower()
                for pat in _excl_names:
                    if name.endswith(pat):
                        return "minified"
                # Size check — minified files are typically one giant line
                try:
                    if f.stat().st_size > settings.max_file_bytes:
                        return "oversized"
                except OSError:
                    pass
                return None

            excl_counts: dict[str, int] = {}
            candidate_files: list[Path] = []
            for f in all_py_files:
                reason = _is_excluded(f)
                if reason:
                    excl_counts[reason] = excl_counts.get(reason, 0) + 1
                else:
                    candidate_files.append(f)

            if excl_counts:
                log.info(
                    "scan.files_excluded",
                    **excl_counts,
                    total_skipped=sum(excl_counts.values()),
                )

            # Large-file filtering: skip files over _MAX_FILE_LINES
            py_files = []
            skipped_large: list[str] = []
            for f in candidate_files:
                try:
                    line_count = sum(1 for _ in open(f, encoding="utf-8", errors="ignore"))
                    if line_count > _MAX_FILE_LINES:
                        log.warning("scan.file_too_large", file=str(f), lines=line_count)
                        skipped_large.append(f.name)
                        continue
                except Exception:
                    pass  # can't count — include file and let parser handle it
                py_files.append(f)

            # Incremental mode: skip files that haven't changed since the last scan
            incremental_mode = (scan.config or {}).get("incremental", False)
            incremental_skipped = 0
            if incremental_mode and py_files:
                try:
                    from app.core.incremental import get_changed_files_for_scan, save_manifest, compute_manifest
                    changed = await get_changed_files_for_scan(source_path, scan.source_ref, scan_id, db)
                    if changed is not None:
                        original_count = len(py_files)
                        py_files = [f for f in py_files if str(f.relative_to(source_path)) in changed]
                        incremental_skipped = original_count - len(py_files)
                        log.info(
                            "incremental.filtered",
                            scan_id=scan_id,
                            kept=len(py_files),
                            skipped=incremental_skipped,
                        )
                    # Save new manifest regardless (so next scan can compare against this one)
                    new_manifest = compute_manifest(source_path)
                    await save_manifest(scan_id, new_manifest)
                except Exception as inc_err:
                    log.warning("incremental.failed", scan_id=scan_id, error=str(inc_err))

            scan.stats = {
                "files_found": len(all_py_files),
                "files_parsed": 0,
                "taint_paths": 0,
                "skipped_large": skipped_large,
                "incremental_skipped": incremental_skipped,
            }
            await db.commit()

            await _broadcast(
                scan_id, "parsing", 0.2,
                f"Parsing {len(py_files)} file{'s' if len(py_files) != 1 else ''}..."
                + (f" ({len(skipped_large)} large files skipped)" if skipped_large else "")
                + (f" ({incremental_skipped} unchanged, incremental)" if incremental_skipped else "")
            )
            await _update_status(db, scan, ScanStatus.TAINT_ANALYSIS, 0.2)

            from app.ingestion.parser import CodeParser
            from app.ingestion.pdg_builder import PDGBuilder
            from app.ingestion.call_graph import CallGraphBuilder
            from app.taint.engine import TaintEngine
            from app.reasoning.pass_1_sanitizer import SanitizerEvaluationPass
            from app.reasoning.pass_2_exploit import ExploitFeasibilityPass
            from app.correlation.fuser import CorrelationFuser
            from app.correlation.dedup import deduplicate
            from app.exploit.poc_generator import PoCGenerator
            from app.exploit.classifier import VulnClassifier
            from app.models.finding import Finding

            parser = CodeParser()
            pdg_builder = PDGBuilder()
            taint_engine = TaintEngine()

            # Parse all files — error isolation: one bad file does not abort the scan
            parsed_files = []
            parse_errors: list[str] = []
            for py_file in py_files:
                try:
                    parsed_files.append(parser.parse_file(str(py_file)))
                except Exception as e:
                    log.warning("scan.parse_error", file=str(py_file), error=str(e))
                    parse_errors.append(py_file.name)

            scan.stats = {**scan.stats, "files_parsed": len(parsed_files), "parse_errors": parse_errors}
            await db.commit()

            if not parsed_files:
                await _update_status(db, scan, ScanStatus.COMPLETE, 1.0)
                scan.completed_at = datetime.utcnow()
                await db.commit()
                await _broadcast(scan_id, "complete", 1.0, "No Python files found")
                return

            # Framework detection — enrich taint engine with framework-specific rules
            from app.ingestion.frameworks import detect_framework, get_framework_profile
            _source_texts = [pf.source for pf in parsed_files]
            detected_framework = detect_framework(_source_texts)
            if detected_framework:
                _profile = get_framework_profile(detected_framework)
                if _profile:
                    taint_engine.apply_framework_profile(_profile)
                    log.info("framework.detected", framework=detected_framework)
                    scan.stats = {**scan.stats, "framework": detected_framework}
                    await db.commit()

            all_findings = []

            if len(parsed_files) > 1:
                taint_paths = await _run_cross_file(
                    parsed_files, pdg_builder, taint_engine,
                    CallGraphBuilder(), source_path, scan_id, scan, db
                )
            else:
                taint_paths = await _run_single_file(
                    parsed_files[0], pdg_builder, taint_engine,
                    scan_id, scan, db
                )

            # ── Unfold graph-folded paths — restore intermediate nodes for full taint path ──
            folded_pdg = taint_engine.get_last_folded_pdg()
            if folded_pdg and taint_paths:
                from app.ingestion.graph_folder import unfold_path
                for tp in taint_paths:
                    tp.path = unfold_path(tp.path, folded_pdg)

            # ── Pre-dedup: collapse paths to the same sink before ANY LLM calls ──────
            # Without this, 30 log_injection paths to the same 3 sinks would burn
            # 30 LLM calls. After pre-dedup, we get at most 3.
            if taint_paths:
                pre_dedup: dict[tuple, object] = {}
                for tp in taint_paths:
                    key = (tp.sink.node.file, tp.sink.node.line, tp.vuln_class)
                    existing = pre_dedup.get(key)
                    if existing is None or tp.confidence > existing.confidence:
                        pre_dedup[key] = tp
                before = len(taint_paths)
                taint_paths = list(pre_dedup.values())
                if before != len(taint_paths):
                    log.info(
                        "scan.pre_dedup",
                        scan_id=scan_id,
                        before=before,
                        after=len(taint_paths),
                        collapsed=before - len(taint_paths),
                    )

            scan.stats = {**scan.stats, "taint_paths": len(taint_paths)}
            await db.commit()

            # Save manifest for non-incremental scans (enables future incremental runs)
            if not incremental_mode:
                try:
                    from app.core.incremental import save_manifest, compute_manifest
                    new_manifest = compute_manifest(source_path)
                    await save_manifest(scan_id, new_manifest)
                except Exception:
                    pass

            # Upload taint analysis artifacts to MinIO
            try:
                from app.core.storage import upload_artifact
                _taint_summary = {
                    "scan_id": scan_id,
                    "files_parsed": scan.stats.get("files_parsed", 0),
                    "framework": scan.stats.get("framework"),
                    "total_paths": len(all_findings),
                }
                await upload_artifact(str(scan_id), "taint_summary", _taint_summary)
            except Exception:
                pass

            if taint_paths:
                await _update_status(db, scan, ScanStatus.REASONING, 0.55)
                await _broadcast(
                    scan_id, "reasoning", 0.55,
                    f"AI analyzing {len(taint_paths)} path{'s' if len(taint_paths) != 1 else ''}"
                    f" (budget: {budget.calls_remaining} LLM calls remaining)..."
                )

                pass1 = SanitizerEvaluationPass(budget=budget)
                pass2 = ExploitFeasibilityPass(budget=budget)
                fuser = CorrelationFuser()
                poc_gen = PoCGenerator()
                classifier = VulnClassifier()

                # Pass 1 + Pass 2 run all LLM calls concurrently — broadcast
                # before/after rather than per-path since they finish together.
                await _broadcast(scan_id, "reasoning", 0.58, "Pass 1: evaluating sanitizers (concurrent)...")
                evaluated = await pass1.run(taint_paths)

                taint_only = sum(1 for ev in evaluated if ev.llm_budget_exhausted)
                await _broadcast(
                    scan_id, "reasoning", 0.72,
                    f"Pass 2: confirming exploit feasibility ({len(evaluated)} paths"
                    + (f", {taint_only} taint-only" if taint_only else "") + ")..."
                )
                confirmed = await pass2.run(evaluated)
                correlated = deduplicate(fuser.fuse(confirmed))

                # Pass 3: Chain discovery on medium/low findings.
                # Skip entirely if every finding is already HIGH or CRITICAL —
                # there is nothing to upgrade via chaining.
                from app.reasoning.pass_3_chains import ChainDiscoveryPass
                from app.models.finding import Finding as FindingModel

                _all_high_or_critical = all(
                    cf.severity in {"high", "critical"}
                    for cf in correlated
                    if not cf.is_false_positive
                )
                if _all_high_or_critical and correlated:
                    log.info(
                        "pass3.skipped",
                        reason="all findings already high/critical",
                        count=len(correlated),
                    )
                    chain_findings = []
                else:
                    chain_pass = ChainDiscoveryPass(budget=budget)
                    chain_findings = await chain_pass.run(correlated)

                await _broadcast(
                    scan_id, "reasoning", 0.88,
                    f"Chain discovery: {len(chain_findings)} chain{'s' if len(chain_findings) != 1 else ''} found"
                )

                for finding_data in correlated:
                    if not finding_data.is_false_positive:
                        try:
                            poc = poc_gen.generate(finding_data)
                            classification = classifier.classify(finding_data)
                            finding = Finding.from_correlated(
                                scan_id=scan.id,
                                finding_data=finding_data,
                                poc=poc,
                                classification=classification,
                            )
                            db.add(finding)
                            all_findings.append(finding)
                        except Exception as e:
                            log.warning("scan.finding_save_error", error=str(e))

                # Save chain findings
                for chain_finding in chain_findings:
                    try:
                        finding = FindingModel.from_chain(
                            scan_id=scan.id,
                            chain_finding=chain_finding,
                        )
                        db.add(finding)
                        all_findings.append(finding)
                    except Exception as e:
                        log.warning("scan.chain_finding_save_error", error=str(e))

            # Persist source_path in stats so the differential endpoint can re-use it
            scan.stats = {**scan.stats, "source_path": source_path}
            await db.commit()

            # ── Concurrent post-pipeline passes ─────────────────────────────────
            # Exploit script generation, Pass 4 business-logic discovery, and
            # Semgrep differential all run concurrently after the core pipeline.
            discovery_mode = (scan.config or {}).get("discovery_mode", False)

            async def _generate_exploit_scripts_task():
                from app.exploit.script_generator import ExploitScriptGenerator
                gen = ExploitScriptGenerator()
                target_findings = [
                    f for f in all_findings
                    if f.vuln_class not in ("chain",) and not getattr(f, "is_false_positive", False)
                    and f.exploit_script is None
                ]
                async def _gen_one(f):
                    try:
                        poc = f.poc or {}
                        script = await gen.generate(
                            cwe_id=f.cwe_id,
                            vuln_class=f.vuln_class,
                            source_file=f.source_file,
                            source_line=f.source_line,
                            sink_file=f.sink_file,
                            sink_line=f.sink_line,
                            sink_code=f.sink_code or "",
                            payload=poc.get("payload", ""),
                            attack_vector=poc.get("attack_vector", ""),
                        )
                        f.exploit_script = script.code
                    except Exception as eg_err:
                        log.warning("exploit_gen.failed", finding_id=str(f.id), error=str(eg_err))
                await asyncio.gather(*[_gen_one(f) for f in target_findings], return_exceptions=True)
                return len(target_findings)

            async def _run_discovery_task():
                if not discovery_mode:
                    return []
                from app.reasoning.pass_4_discovery import BusinessLogicDiscoveryPass
                disc = BusinessLogicDiscoveryPass(budget=budget)
                return await disc.run(parsed_files, source_path)

            async def _run_semgrep_task():
                from app.analysis.semgrep_runner import run_semgrep, compute_differential, DifferentialResult
                try:
                    sg_findings = await run_semgrep(source_path)
                except FileNotFoundError:
                    result = compute_differential(all_findings, [])
                    result.semgrep_available = False
                    result.semgrep_error = "Semgrep is not installed."
                    return result
                return compute_differential(all_findings, sg_findings)

            await _broadcast(scan_id, "reasoning", 0.91,
                             "Generating exploits, running discovery and Semgrep analysis...")

            post_results = await asyncio.gather(
                _generate_exploit_scripts_task(),
                _run_discovery_task(),
                _run_semgrep_task(),
                return_exceptions=True,
            )

            # Unpack results — each may be an exception if it failed
            exploit_count = post_results[0] if not isinstance(post_results[0], BaseException) else 0
            discovery_results = post_results[1] if not isinstance(post_results[1], BaseException) else []
            semgrep_diff = post_results[2] if not isinstance(post_results[2], BaseException) else None

            if isinstance(post_results[0], BaseException):
                log.warning("exploit_gen.task_failed", error=str(post_results[0]))
            if isinstance(post_results[1], BaseException):
                log.warning("pass4.task_failed", error=str(post_results[1]))
            if isinstance(post_results[2], BaseException):
                log.warning("semgrep.task_failed", error=str(post_results[2]))

            # Save discovery findings to DB
            discovery_saved = 0
            if discovery_results:
                for df in discovery_results:
                    try:
                        disc_orm = FindingModel(
                            id=uuid.uuid4(),
                            scan_id=scan.id,
                            title=df.title,
                            severity=df.severity,
                            confidence=df.confidence,
                            vuln_class=df.vuln_type,
                            cwe_id=df.cwe_id,
                            owasp_category=df.owasp_category,
                            description=df.description + (f"\n\nAttack scenario: {df.attack_scenario}" if df.attack_scenario else ""),
                            source_file=df.file,
                            source_line=df.line,
                            source_code=df.code_snippet or None,
                            sink_file=df.file,
                            sink_line=df.line,
                            sink_code=df.code_snippet or None,
                            taint_path={"type": "business_logic_discovery", "function": df.function_name},
                            attack_flow={"nodes": [], "edges": [], "type": "business_logic_discovery"},
                            llm_reasoning=df.attack_scenario,
                            llm_confidence=df.confidence,
                            remediation={"summary": df.remediation} if df.remediation else None,
                            triage_status="open",
                        )
                        db.add(disc_orm)
                        all_findings.append(disc_orm)
                        discovery_saved += 1
                    except Exception as e:
                        log.warning("pass4.save_error", error=str(e))
                if discovery_saved:
                    await db.commit()

            # Store Semgrep differential summary in scan stats
            if semgrep_diff is not None:
                diff_summary = {
                    "semgrep_available": semgrep_diff.semgrep_available,
                    "vexis_total": semgrep_diff.vexis_total,
                    "semgrep_total": semgrep_diff.semgrep_total,
                    "vexis_only": len(semgrep_diff.vexis_only),
                    "semgrep_only": len(semgrep_diff.semgrep_only),
                    "overlap": len(semgrep_diff.overlap),
                }
                full_differential = {
                    "semgrep_available": semgrep_diff.semgrep_available,
                    "semgrep_error": getattr(semgrep_diff, "semgrep_error", None),
                    "summary": diff_summary,
                    "vexis_only": semgrep_diff.vexis_only,
                    "semgrep_only": [
                        {
                            "rule_id": sf.rule_id,
                            "file": sf.file,
                            "line": sf.line,
                            "message": sf.message,
                            "severity": sf.severity,
                            "vuln_class": sf.vuln_class,
                            "cwe": sf.cwe,
                        }
                        for sf in semgrep_diff.semgrep_only
                    ],
                    "overlap": semgrep_diff.overlap,
                }
                scan.stats = {**scan.stats, "semgrep_summary": diff_summary, "differential": full_differential}

            log.info(
                "post_pipeline.done",
                exploit_scripts=exploit_count,
                discovery_findings=discovery_saved,
                semgrep_overlap=getattr(semgrep_diff, "overlap", None) and len(semgrep_diff.overlap),
            )
            await db.commit()

            # Second-order injection analysis (experimental — scans for DB write→read→sink patterns)
            try:
                from app.analysis.second_order import analyze_second_order
                so_findings = analyze_second_order(parsed_files)
                if so_findings:
                    log.info("second_order.findings", count=len(so_findings))
                    for so_finding in so_findings:
                        # Convert to Finding ORM object
                        so_orm = Finding(
                            id=uuid.uuid4(),
                            scan_id=scan.id,
                            title=f"Second-Order {so_finding.cwe_id}: {so_finding.description[:60]}",
                            severity="high",
                            confidence=0.6,
                            vuln_class=so_finding.vuln_class,
                            cwe_id=so_finding.cwe_id,
                            owasp_category="A03:2021 – Injection",
                            description=so_finding.description,
                            source_file=so_finding.write_file,
                            source_line=so_finding.write_line,
                            source_code=so_finding.write_code,
                            sink_file=so_finding.sink_file,
                            sink_line=so_finding.sink_line,
                            sink_code=so_finding.sink_code,
                            taint_path={"type": "second_order", "read_file": so_finding.read_file, "read_line": so_finding.read_line},
                            attack_flow={"nodes": [], "edges": [], "type": "second_order"},
                            triage_status="open",
                        )
                        db.add(so_orm)
                    await db.commit()
            except Exception as e:
                log.warning("second_order.analysis_failed", error=str(e))

            # Race condition / TOCTOU detection (CWE-362)
            try:
                from app.analysis.race_detector import detect_race_conditions
                race_findings = detect_race_conditions(parsed_files)
                for rf in race_findings:
                    race_orm = Finding(
                        id=uuid.uuid4(),
                        scan_id=scan.id,
                        title=f"TOCTOU Race Condition: {rf.check_code[:50]}",
                        severity="medium",
                        confidence=0.7,
                        vuln_class="race_condition",
                        cwe_id="CWE-362",
                        owasp_category="A04:2021 – Insecure Design",
                        description=rf.description,
                        source_file=rf.file,
                        source_line=rf.check_line,
                        source_code=rf.check_code,
                        sink_file=rf.file,
                        sink_line=rf.act_line,
                        sink_code=rf.act_code,
                        taint_path={"type": "race_condition"},
                        attack_flow={"nodes": [], "edges": [], "type": "race_condition"},
                        triage_status="open",
                    )
                    db.add(race_orm)
                if race_findings:
                    await db.commit()
            except Exception as e:
                log.warning("race_detector.failed", error=str(e))

            # Auth bypass / CWE-287 detection
            try:
                from app.analysis.auth_analyzer import detect_auth_issues
                auth_findings = detect_auth_issues(parsed_files)
                for af in auth_findings:
                    auth_orm = Finding(
                        id=uuid.uuid4(),
                        scan_id=scan.id,
                        title=f"Auth Bypass: {af.vuln_type.replace('_', ' ').title()} at {af.line}",
                        severity="high",
                        confidence=0.65,
                        vuln_class="auth_bypass",
                        cwe_id="CWE-287",
                        owasp_category="A07:2021 – Identification and Authentication Failures",
                        description=af.description,
                        source_file=af.file,
                        source_line=af.line,
                        source_code=af.code,
                        sink_file=af.file,
                        sink_line=af.line,
                        sink_code=af.code,
                        taint_path={"type": "auth_bypass"},
                        attack_flow={"nodes": [], "edges": [], "type": "auth_bypass"},
                        triage_status="open",
                    )
                    db.add(auth_orm)
                if auth_findings:
                    await db.commit()
            except Exception as e:
                log.warning("auth_analyzer.failed", error=str(e))

            taint_only_count = sum(
                1 for f in all_findings
                if f.llm_reasoning and "budget exhausted" in f.llm_reasoning
            )
            scan.stats = {
                **scan.stats,
                "llm_calls": budget.calls_made,
                "taint_only_findings": taint_only_count,
                "discovery_findings": discovery_saved,
                "exploit_scripts_generated": exploit_count if not isinstance(exploit_count, BaseException) else 0,
            }
            await db.commit()
            await _update_status(db, scan, ScanStatus.COMPLETE, 1.0)
            scan.completed_at = datetime.utcnow()
            await db.commit()

            completion_msg = f"Scan complete — {len(all_findings)} finding{'s' if len(all_findings) != 1 else ''} found"
            if taint_only_count:
                completion_msg += f" ({taint_only_count} scored taint-only, LLM budget reached)"
            await _broadcast(scan_id, "complete", 1.0, completion_msg)
            log.info("scan.complete", scan_id=scan_id, findings=len(all_findings), llm_calls=budget.calls_made)

        except Exception as e:
            log.error("scan.failed", scan_id=scan_id, error=str(e), exc_info=True)
            scan.status = ScanStatus.FAILED
            scan.error_message = str(e)
            scan.completed_at = datetime.utcnow()
            await db.commit()
            await _broadcast(scan_id, "failed", 0.0, f"Scan failed: {str(e)[:100]}")
        finally:
            if _temp_dir:
                import shutil
                shutil.rmtree(_temp_dir, ignore_errors=True)


async def _run_single_file(parsed, pdg_builder, taint_engine, scan_id, scan, db):
    """Intra-file taint analysis for a single file."""
    pdg = pdg_builder.build(parsed)
    paths = taint_engine.analyze(pdg)
    await _broadcast(
        scan_id, "taint_analysis", 0.5,
        f"Found {len(paths)} taint path{'s' if len(paths) != 1 else ''}"
    )
    return paths


async def _run_cross_file(
    parsed_files, pdg_builder, taint_engine, cg_builder,
    project_root, scan_id, scan, db
):
    """Cross-file taint analysis for a multi-file project."""
    call_graph = cg_builder.build_project(parsed_files, project_root=project_root)

    pdgs = {}
    for i, pf in enumerate(parsed_files):
        try:
            pdg = pdg_builder.build(pf)
            pdgs[pf.path] = pdg
            progress = 0.2 + 0.25 * (i + 1) / len(parsed_files)
            await _broadcast(
                scan_id, "taint_analysis", progress,
                f"PDG built: {Path(pf.path).name} ({i + 1}/{len(parsed_files)})"
            )
        except Exception as e:
            log.warning("scan.pdg_error", file=pf.path, error=str(e))

    if not pdgs:
        return []

    await _broadcast(scan_id, "taint_analysis", 0.48,
                     f"Cross-file linking {len(pdgs)} files...")

    paths = taint_engine.analyze_project(pdgs, call_graph)
    await _broadcast(
        scan_id, "taint_analysis", 0.5,
        f"Found {len(paths)} taint path{'s' if len(paths) != 1 else ''} (cross-file)"
    )
    return paths


async def _update_status(db, scan: Scan, status: ScanStatus, progress: float | None = None) -> None:
    scan.status = status
    if progress is not None:
        scan.progress = progress
    await db.commit()


async def _fetch_source(scan: Scan) -> str:
    """Returns path to directory containing source code on disk."""
    from app.core.git_ops import clone_repo

    if scan.source_type == "github_url":
        return await clone_repo(scan.source_ref)

    elif scan.source_type == "file_upload":
        return scan.source_ref

    elif scan.source_type == "raw_code":
        code = scan.source_ref
        tmp_dir = tempfile.mkdtemp(prefix="vexis_")

        parts = _FILE_MARKER_RE.split(code)
        if len(parts) > 1:
            i = 1
            while i + 1 < len(parts):
                filename = parts[i].strip()
                content = parts[i + 1]
                safe_name = Path(filename).name
                _supported_exts = {".py", ".js", ".ts", ".jsx", ".tsx"}
                if not any(safe_name.endswith(ext) for ext in _supported_exts):
                    safe_name += ".py"
                file_path = os.path.join(tmp_dir, safe_name)
                with open(file_path, "w", encoding="utf-8") as fh:
                    fh.write(content)
                log.info("scan.multi_file_written", file=safe_name)
                i += 2
        else:
            code_path = os.path.join(tmp_dir, "scan_target.py")
            with open(code_path, "w", encoding="utf-8") as fh:
                fh.write(code)
            log.info("scan.raw_code_written", path=code_path)

        return tmp_dir

    elif scan.source_type == "directory":
        if not os.path.isdir(scan.source_ref):
            raise ValueError(f"Directory not found: {scan.source_ref}")
        return scan.source_ref

    else:
        raise ValueError(f"Unsupported source type: {scan.source_type}")
