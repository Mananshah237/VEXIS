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
            await _update_status(db, scan, ScanStatus.PARSING)
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

            # Large-file filtering: skip files over _MAX_FILE_LINES
            py_files = []
            skipped_large: list[str] = []
            for f in all_py_files:
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
            await _update_status(db, scan, ScanStatus.TAINT_ANALYSIS)

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
                await _update_status(db, scan, ScanStatus.COMPLETE)
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
                await _update_status(db, scan, ScanStatus.REASONING)
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

                evaluated = await pass1.run(taint_paths)

                for j, ev in enumerate(evaluated):
                    await _broadcast(
                        scan_id, "reasoning",
                        0.55 + 0.3 * (j + 1) / max(len(evaluated), 1),
                        f"AI reasoning: path {j + 1}/{len(evaluated)}"
                        + (" [taint-only]" if ev.llm_budget_exhausted else "")
                    )

                confirmed = await pass2.run(evaluated)
                correlated = deduplicate(fuser.fuse(confirmed))

                # Pass 3: Chain discovery on medium/low findings
                from app.reasoning.pass_3_chains import ChainDiscoveryPass
                from app.models.finding import Finding as FindingModel

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
            }
            await db.commit()
            await _update_status(db, scan, ScanStatus.COMPLETE)
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


async def _update_status(db, scan: Scan, status: ScanStatus) -> None:
    scan.status = status
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
                if not safe_name.endswith(".py"):
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
