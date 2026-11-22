"""AegisFlight command-line interface (the ``aegis`` entry point).

Subcommands:
    aegis simulate    run one telemetry session through the IDS and print results
    aegis benchmark   run the full detection benchmark -> artifacts/
    aegis train       train the anomaly model on benign flights
    aegis serve       start the FastAPI backend (live dashboard API + WebSocket)
    aegis verify-log  verify a SQLite event log's SHA-256 hash chain
    aegis version     print version

Run ``aegis <cmd> -h`` for per-command options.
"""

from __future__ import annotations

import argparse
import contextlib
import os
import sys
from pathlib import Path

from .. import __version__


def _cmd_simulate(args: argparse.Namespace) -> int:
    from ..benchmark.runner import run_session
    from ..config import load_config
    from ..logging import EventStore
    from ..metrics import evaluate
    from ..model_integrity import resolve_model_or_exit

    cfg = load_config()
    model = resolve_model_or_exit(args.model, no_model=args.no_model,
                                  allow_unverified=args.allow_unverified_model)
    print(f"Simulating scenario='{args.attack}' seed={args.seed} route={args.route or 'default'} "
          f"model={'off' if model is None else model}")
    res = run_session(
        cfg,
        args.attack,
        seed=args.seed,
        route=args.route,
        model_path=model,
        allow_unverified_model=args.allow_unverified_model,
    )

    alerts = [a for a in res.assessments if a.is_alert]
    scored = [r for r in res.records if r.scored]
    ev = evaluate([r.true_label for r in scored], [r.pred_label for r in scored])

    print(f"\nDecisions: {res.n_decisions}  messages: {res.n_messages}  "
          f"throughput: {res.throughput_msgs_per_s:.0f} msg/s")
    if args.attack not in ("benign", "none"):
        print(f"Attack window: {res.window[0]:.0f}-{res.window[1] if res.window[1] < 1e17 else 'end'}s"
              f"  time-to-detect: {res.time_to_detect_s}s  recall: {ev.binary.recall:.2f}")
    print(f"FPR (this session): {ev.binary.fpr:.3f}")
    print(f"\nAlerts raised: {len(alerts)}")
    for a in alerts[:8]:
        print(f"  t={a.t:6.1f}s  {a.severity.value:9} {a.attack_type.value:22} "
              f"score={a.threat_score:.2f} conf={a.confidence:.2f}")
        for e in a.evidence[:2]:
            print(f"           └─ {e}")

    if args.db:
        store = EventStore(args.db)
        run_id = f"{args.attack}-{args.seed}"
        store.start_run(run_id, label=args.attack)
        for a in alerts:
            store.log_event(a, run_id)
        cs = store.verify_chain(run_id)
        print(f"\nLogged {len(alerts)} alerts to {args.db} (run={run_id}); "
              f"chain: {'OK' if cs.ok else 'BROKEN'} ({cs.length} events)")
        store.close()
    return 0


def _cmd_benchmark(args: argparse.Namespace) -> int:
    from ..benchmark.harness import run_benchmark
    from ..config import load_config
    from ..model_integrity import resolve_model_or_exit

    cfg = load_config()
    model = resolve_model_or_exit(args.model, no_model=args.no_model,
                                  allow_unverified=args.allow_unverified_model)
    result = run_benchmark(
        cfg,
        seeds=args.seeds,
        model_path=model,
        out_dir=args.out,
        allow_unverified_model=args.allow_unverified_model,
    )
    b = result["binary"]
    print(f"accuracy={b['accuracy']} recall={b['recall_tpr']} FPR={b['fpr']} F1={b['f1']}")
    if not args.no_figures:
        from ..benchmark import plots
        plots.generate_all(cfg, result, "artifacts/figures")
    print(f"Artifacts -> {args.out}/")
    return 0


def _cmd_train(args: argparse.Namespace) -> int:
    # scripts/ is not an importable package, so the trainer logic is inlined
    # here (kept in sync with scripts/train_models.py).
    import platform as _pf
    from datetime import UTC, datetime
    from pathlib import Path

    import joblib
    import numpy as np
    import sklearn
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler

    from ..benchmark.dataset import collect_benign_dataset
    from ..config import load_config
    from ..detectors.anomaly import combined_anomaly_raw
    from ..features.extractor import ML_FEATURES

    cfg = load_config()
    acfg = cfg.detector["anomaly"]
    ds = collect_benign_dataset(cfg, n_sessions=args.sessions, seed=args.seed)
    split = ds.split_by_session(seed=args.seed)
    Xtr, Xva = split["train"], split["val"]
    scaler = StandardScaler().fit(Xtr)
    model = IsolationForest(n_estimators=int(acfg["n_estimators"]),
                            contamination=float(acfg["contamination"]),
                            random_state=args.seed, n_jobs=-1).fit(scaler.transform(Xtr))
    Xtr_s = scaler.transform(Xtr)
    iso = -model.score_samples(Xtr_s)
    maha = np.linalg.norm(Xtr_s, axis=1)
    bundle = {"model": model, "scaler": scaler, "feature_names": list(ML_FEATURES),
              "iso_mean": float(iso.mean()), "iso_std": float(iso.std() or 1e-3),
              "maha_mean": float(maha.mean()), "maha_std": float(maha.std() or 1e-3)}
    va = combined_anomaly_raw(bundle, Xva)
    bundle["score_thr"] = float(va.mean() + 3.0 * va.std())
    bundle["score_scale"] = float(max(va.std(), 1e-3))
    bundle["metadata"] = {"created": datetime.now(UTC).isoformat(),
                          "sklearn_version": sklearn.__version__,
                          "python_version": _pf.python_version(), "seed": args.seed,
                          "n_sessions": args.sessions}
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, args.out)
    print(f"Trained on {len(Xtr)} benign vectors; saved -> {args.out}")
    return 0


_LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "::1")


def _serve_env(spec, args: argparse.Namespace) -> dict[str, str]:
    """Every ``AEGIS_*`` key the app reads (``backend/sources.py:spec_from_env``, ``backend/app.py``), ALL set,
    so a stale variable in the operator's shell can never change the source."""
    return {
        "AEGIS_SOURCE": spec.kind, "AEGIS_SERIAL_PORT": spec.port or "", "AEGIS_BAUD": str(spec.baud),
        "AEGIS_ALLOW_URL": "1" if spec.allow_url else "0", "AEGIS_TLOG": spec.tlog or "",
        "AEGIS_REPLAY_SPEED": repr(spec.speed), "AEGIS_UDP_PORT": str(spec.udp_port or ""),
        "AEGIS_CONFIG_DIR": spec.config_dir or "", "AEGIS_ML": "",  # "" -> SourceSpec default (SIM only)
        "AEGIS_RECONNECT": "1" if spec.reconnect else "0", "AEGIS_DB": args.db or "",
        "AEGIS_SERVE_HOST": args.host,
        "AEGIS_GCS_NOTIFY": "1" if getattr(args, "gcs_notify", False) else "0",
        "AEGIS_GCS_NOTIFY_HOST": getattr(args, "gcs_notify_host", "127.0.0.1"),
        "AEGIS_GCS_NOTIFY_PORT": str(getattr(args, "gcs_notify_port", 14550)),
        "AEGIS_DEFENSE_MODE": spec.defense_mode,
    }


def _cmd_serve(args: argparse.Namespace) -> int:
    from ..backend.sources import SourceSpec

    try:  # validated before anything starts: a bad source is an error, never a silent SIM fallback
        spec = SourceSpec(kind=args.source, port=args.serial_port, baud=args.baud, allow_url=args.allow_url,
                          tlog=args.tlog, speed=args.replay_speed, udp_port=args.udp_port,
                          config_dir=args.config_dir, reconnect=not args.no_reconnect,
                          defense_mode=args.defense_mode,
                          gcs_notify=args.gcs_notify, gcs_notify_host=args.gcs_notify_host,
                          gcs_notify_port=args.gcs_notify_port,
                          signing_key_file=getattr(args, "signing_key_file", None),
                          mgmt_key_file=getattr(args, "mgmt_key_file", None))
        for flag, path in (("--signing-key-file", spec.signing_key_file), ("--mgmt-key-file", spec.mgmt_key_file)):
            if path:
                from ..detectors.crossend import load_signing_key

                try:
                    load_signing_key(path)
                except (OSError, ValueError, UnicodeDecodeError) as exc:
                    raise ValueError(f"bad {flag}: {exc}") from exc
    except ValueError as exc:
        print(f"aegis serve: {exc}", file=sys.stderr)
        return 2
    if spec.kind != "sim":
        if args.reload:  # the reloader restarts the worker on every edit, re-opening the source each time
            print("aegis serve: --reload is simulation-only", file=sys.stderr)
            return 2
        if args.host not in _LOOPBACK_HOSTS:  # live telemetry (possibly a real position) stays on this machine
            print(f"aegis serve: a {spec.environment} source is served on loopback only (--host 127.0.0.1)",
                  file=sys.stderr)
            return 2
    try:
        import uvicorn
    except ImportError:
        print("uvicorn not installed", file=sys.stderr)
        return 1
    os.environ.update(_serve_env(spec, args))
    # kept out of _serve_env (its key set is fixed); a stale shell value is cleared when no key is given
    if spec.signing_key_file:
        os.environ["AEGIS_SIGNING_KEY_FILE"] = spec.signing_key_file
    else:
        os.environ.pop("AEGIS_SIGNING_KEY_FILE", None)
    if spec.mgmt_key_file:
        os.environ["AEGIS_MGMT_KEY_FILE"] = spec.mgmt_key_file
    else:
        os.environ.pop("AEGIS_MGMT_KEY_FILE", None)
    print(f"aegis serve: source {spec.environment} ({spec.describe()['label']}) on http://{args.host}:{args.port}")
    uvicorn.run("aegisflight.backend.app:app", host=args.host, port=args.port, reload=args.reload)
    return 0


def _cmd_ips_bridge(args: argparse.Namespace) -> int:
    """Run the inline IPS bridge between a flight controller port and a GCS/radio port."""
    import json
    import time

    from ..hal.inline_ips import InlineIpsBridge
    from ..sources.mavlink_serial import SerialMavlinkTransport, may_reach_vehicle

    if args.fc_port == args.gcs_port:
        print("aegis ips-bridge: --fc-port and --gcs-port must differ", file=sys.stderr)
        return 2
    if args.defense_mode == "active-ips" and may_reach_vehicle(args.fc_port):
        print(f"aegis ips-bridge: refusing --defense-mode active-ips on --fc-port {args.fc_port}: a serial device may "
              "be a physical flight controller, which is receive-only. Use a socket:// SITL link.", file=sys.stderr)
        return 2
    try:
        fc = SerialMavlinkTransport(args.fc_port, baudrate=args.fc_baud, allow_url=args.allow_url,
                                    accept_unverified_ids=True)
        gcs = SerialMavlinkTransport(args.gcs_port, baudrate=args.gcs_baud, allow_url=args.allow_url,
                                     accept_unverified_ids=True)
    except ValueError as exc:
        print(f"aegis ips-bridge: {exc}", file=sys.stderr)
        return 2
    from ..detectors.crossend import load_signing_key  # its errors never quote key bytes

    key = None
    if args.signing_key_file:
        try:
            key = load_signing_key(args.signing_key_file)
        except (OSError, ValueError) as exc:
            print(f"aegis ips-bridge: bad --signing-key-file: {exc}", file=sys.stderr)
            return 2
    mgmt_key = None
    if args.mgmt_key_file:
        try:
            mgmt_key = load_signing_key(args.mgmt_key_file)
        except (OSError, ValueError) as exc:
            print(f"aegis ips-bridge: bad --mgmt-key-file: {exc}", file=sys.stderr)
            return 2
        if not args.mgmt_state:
            print("aegis ips-bridge: refusing --mgmt-key-file without --mgmt-state: without the persisted anti-replay state "
                  "a restart would accept a recorded management command again", file=sys.stderr)
            return 2
    if (args.filter_override_file or args.filter_lockout_failopen_s is not None) and not args.vehicle_uplink_filter:
        print("aegis ips-bridge: --filter-override-file / --filter-lockout-failopen-s only apply with --vehicle-uplink-filter", file=sys.stderr)
        return 2
    if args.vehicle_uplink_filter and key is None:
        print("aegis ips-bridge: --vehicle-uplink-filter needs --signing-key-file: without a key the filter cannot tell the pilot "
              "from a forger and would block the pilot.", file=sys.stderr)
        return 2
    if args.vehicle_uplink_filter and args.defense_mode == "active-ips":
        print("aegis ips-bridge: --vehicle-uplink-filter is the alternative to --defense-mode active-ips on a vehicle link; "
              "use passive or advisory with it.", file=sys.stderr)
        return 2
    if args.defense_mode == "active-ips" and key is None and not args.allow_unsigned:
        print("aegis ips-bridge: refusing --defense-mode active-ips without --signing-key-file: an unsigned link "
              "cannot stop a counter-tracking forger. Provision a key, or pass --allow-unsigned to accept the risk.",
              file=sys.stderr)
        return 2
    token = None
    if args.control_token_file:
        try:
            token = Path(args.control_token_file).read_text(encoding="utf-8").strip()
        except (OSError, UnicodeDecodeError) as exc:
            print(f"aegis ips-bridge: bad --control-token-file: {exc}", file=sys.stderr)
            return 2
        if not token:
            print("aegis ips-bridge: --control-token-file is empty", file=sys.stderr)
            return 2
    import ipaddress

    status_host = args.status_host
    try:
        loopback = status_host == "localhost" or ipaddress.ip_address(status_host).is_loopback
    except ValueError:
        loopback = False
    if not loopback and token is None:
        print(f"aegis ips-bridge: refusing --status-host {status_host}: a non-loopback status API requires "
              "--control-token-file", file=sys.stderr)
        return 2
    # Resolve (and hash-check) the optional model BEFORE any run directory or event store exists: a refused model must
    # not leave an empty evidence run behind, and the manifest must record the model the bridge really runs with.
    model_path: str | None = None
    model_extra: dict[str, object] | None = None
    if args.model:
        from ..model_integrity import check_model, resolve_model_or_exit

        model_path = resolve_model_or_exit(args.model, allow_unverified=args.allow_unverified_model)
        model_extra = {"model_verification": check_model(model_path).status,
                       "allow_unverified_model": bool(args.allow_unverified_model)}
    archive = run_prov = None
    if args.run_dir:
        # evidence run (issue #25): clean tree or --allow-dirty (stamped NOT-REPRODUCIBLE); raw frames, decisions,
        # actions and a full manifest land in the run directory
        from ..hal.run_archive import BridgeRunArchive
        from ..run_provenance import DirtyTreeError, begin_run

        try:
            run_prov = begin_run(allow_dirty=args.allow_dirty, profile_dir=args.config_dir,
                                 model_path=model_path, extra=model_extra)  # ML off (model_path None) -> "none"
            archive = BridgeRunArchive(args.run_dir)
        except DirtyTreeError:
            return 2  # require_clean_tree already printed the reason to stderr
        except FileExistsError as exc:
            print(f"aegis ips-bridge: {exc}", file=sys.stderr)
            return 2
        if args.db is None:
            args.db = str(Path(args.run_dir) / "events.sqlite")
    store = anchor_writer = None
    if args.db:
        from ..logging import AnchorWriter, EventStore

        store = EventStore(args.db)
        run_id = time.strftime("ips-%Y%m%d-%H%M%S")
        store.start_run(run_id, label="ips-bridge")
        anchor_writer = AnchorWriter(store)
    else:
        run_id = "ips-bridge"
    try:  # e.g. an unreadable / corrupt / unwritable --mgmt-state: refuse to start, never run without replay state
        bridge = InlineIpsBridge(fc, gcs, config_dir=args.config_dir, mode=args.defense_mode,
                                 trusted_sysids=tuple(args.trusted_sysid) if args.trusted_sysid else None,
                                 store=store, run_id=run_id, secret_key=key,
                                 allow_unsigned_from_trusted=args.signing_permissive,
                                 signing_max_age_s=args.signing_max_age_s, signing_state_path=args.signing_state,
                                 ekf_secondary=args.ekf_secondary, crossend_interval_s=args.crossend_interval,
                                 firmware_dir=args.firmware_dir, firmware_recheck_s=args.firmware_recheck_s,
                                 contested_policy=args.contested_policy, replay_memory=args.replay_memory,
                                 gcs_alerts=args.gcs_alerts == "on", alert_min_interval_s=args.alert_min_interval,
                                 mgmt_status_interval_s=args.mgmt_status_interval,
                                 mgmt_max_bytes_per_s=args.mgmt_max_bytes_per_s, mgmt_key=mgmt_key,
                                 mgmt_state_path=args.mgmt_state, lock_posture_file=args.lock_posture_file,
                                 mgmt_max_cmd_age_s=args.mgmt_max_age_s,
                                 audit_log_path=args.audit_log,
                                 mgmt_enable=bool(args.mgmt_enable),
                                 unsigned_acknowledged=args.allow_unsigned and key is None and args.defense_mode == "active-ips",
                                 vehicle_filter=args.vehicle_uplink_filter, filter_override_file=args.filter_override_file,
                                 filter_lockout_failopen_s=args.filter_lockout_failopen_s,
                                 model_path=model_path, allow_unverified_model=args.allow_unverified_model,
                                 on_alarm=lambda m: print(f"aegis ips-bridge: ALARM {m}", flush=True), archive=archive)
    except ValueError as exc:
        print(f"aegis ips-bridge: {exc}", file=sys.stderr)
        return 2
    fc.start()
    gcs.start()
    bridge.start()
    status_srv = None
    if args.status_port:
        from ..hal.status_server import BridgeStatusServer

        try:
            status_srv = BridgeStatusServer(
                bridge, args.status_port, host=status_host, control_token=token, signing_configured=key is not None,
                allow_unsigned=args.allow_unsigned and args.defense_mode == "active-ips").start()
            if not loopback:
                print(f"aegis ips-bridge: WARNING status API reachable from the network on {status_host}:"
                      f"{args.status_port} (posture control requires the token)", flush=True)
        except OSError as exc:
            print(f"aegis ips-bridge: cannot bind status port: {exc}", file=sys.stderr)
    print(f"aegis ips-bridge: {args.fc_port} <-> {args.gcs_port}, posture {args.defense_mode}", flush=True)
    if args.vehicle_uplink_filter:
        print("aegis ips-bridge: NOTICE --vehicle-uplink-filter is on: forged, unsigned, replayed and wrong-key control frames from the GCS "
              "are DROPPED before the flight controller once a validly signed ground-station frame has proved the key (until then it only "
              "reports). The downlink is untouched and no counter-command is sent. Not switchable over the radio or the status API.", flush=True)
        if args.filter_override_file:
            print(f"aegis ips-bridge: local override: while {args.filter_override_file} exists the filter only reports", flush=True)
    if args.defense_mode == "active-ips" and key is None:
        print("aegis ips-bridge: NOTICE active-ips without signing acknowledged via --allow-unsigned", flush=True)
    end = None if args.seconds is None else time.monotonic() + args.seconds
    try:
        while end is None or time.monotonic() < end:
            time.sleep(min(args.status_interval, 0.5) if end is not None else args.status_interval)
            if anchor_writer is not None:
                anchor_writer.maybe_write(run_id)
            print(json.dumps(bridge.status()), flush=True)
    except KeyboardInterrupt:
        pass
    finally:
        if status_srv is not None:
            status_srv.close()
        bridge.close()
        if anchor_writer is not None:
            with contextlib.suppress(Exception):
                anchor_writer.write_now(run_id, force=True)
        if store is not None:
            store.close()
        if archive is not None and run_prov is not None:
            from ..run_provenance import finish_run, write_manifest

            try:
                archive_stats = archive.close()
            except Exception as exc:  # noqa: BLE001 - the manifest is still written; the archive is marked incomplete
                archive_stats = {"complete": False, "writer_error": f"{type(exc).__name__}: {exc}"}
            run_prov["bridge"] = {"fc_port": args.fc_port, "gcs_port": args.gcs_port, "defense_mode": args.defense_mode,
                                  "signing": key is not None, "final_status": bridge.status(),
                                  "archive": archive_stats}
            write_manifest(args.run_dir, finish_run(run_prov))
            print(f"aegis ips-bridge: run archived in {args.run_dir} ({run_prov['status']})", flush=True)
    return 0


def _cmd_fw_manifest(args: argparse.Namespace) -> int:
    from ..integrity.verifier import FirmwareVerifier

    v = FirmwareVerifier(args.dir)
    manifest = v.build_manifest()
    comps = manifest["components"]
    if not comps:
        print(f"aegis fw-manifest: no *.bin files in {args.dir}; the manifest is empty", file=sys.stderr)
        return 2
    for name, digest in comps.items():
        print(f"{digest}  {name}")
    print(f"manifest written: {v.manifest_path} ({len(comps)} components). Keep it with the files and treat it as trusted: "
          "an attacker who can rewrite both defeats the check (it is not signed).")
    return 0


def _cmd_verify_log(args: argparse.Namespace) -> int:
    from ..logging import EventStore, find_diverted_anchor_files, verify_anchors

    store = EventStore(args.db, read_only=True)
    try:
        cs = store.verify_chain()
        print(f"events: {cs.length}  chain: {'OK' if cs.ok else 'BROKEN'}  {cs.detail}")
        ok = cs.ok
        if getattr(args, "verify_actions", False):
            acs = store.verify_actions_chain()
            print(f"actions: {acs.length}  chain: {'OK' if acs.ok else 'BROKEN'}  {acs.detail}")
            ok = ok and acs.ok
        if getattr(args, "anchors", None):
            av = verify_anchors(store, args.anchors)
            for w in av.warnings:
                print(f"anchor warning: {w}", file=sys.stderr)
            for err in av.errors:
                print(f"anchor error: {err}", file=sys.stderr)
            print(
                f"anchors: {av.anchors_checked}  signed: {av.signed_anchors}  "
                f"unsigned: {av.unsigned_anchors}  status: {'OK' if av.ok else 'FAILED'}"
            )
            ok = ok and av.ok
            # an AnchorWriter that found a corrupt tail wrote its later anchors to sibling files: verify each as
            # its own chain and say so, never report only the (damaged) original as if it were the whole story
            for sib in find_diverted_anchor_files(args.anchors):
                print(f"anchor warning: {args.anchors} had a corrupt tail when a later run resumed; "
                      f"anchors from that run are in {sib.name}", file=sys.stderr)
                sv = verify_anchors(store, sib)
                for err in sv.errors:
                    print(f"anchor error ({sib.name}): {err}", file=sys.stderr)
                print(f"diverted anchors {sib.name}: {sv.anchors_checked}  signed: {sv.signed_anchors}  "
                      f"unsigned: {sv.unsigned_anchors}  status: {'OK' if sv.ok else 'FAILED'}")
                ok = ok and sv.ok
    finally:
        store.close()
    return 0 if ok else 2


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="aegis", description="AegisFlight UAV IDS")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("simulate", help="run one IDS session and print results")
    s.add_argument("--attack", default="benign",
                   help="benign|gps_spoofing|mavlink_anomaly|command_injection|"
                        "telemetry_manipulation|dos|firmware_integrity")
    s.add_argument("--seed", type=int, default=42)
    s.add_argument("--route", default=None, help="survey_box|out_and_back|perimeter")
    s.add_argument("--model", default="models/isoforest.joblib")
    s.add_argument("--no-model", action="store_true", help="explicit ML-off run (rule + physics only)")
    s.add_argument("--allow-unverified-model", action="store_true",
                   help="use a model whose SHA-256 differs from models/MODELS.sha256 (e.g. `aegis train` output)")
    s.add_argument("--db", default=None, help="log alerts to this SQLite path")
    s.set_defaults(func=_cmd_simulate)

    b = sub.add_parser("benchmark", help="run the full detection benchmark")
    b.add_argument("--seeds", type=int, nargs="+", default=[1, 2, 3, 4, 5, 6])
    b.add_argument("--out", default="artifacts/benchmarks")
    b.add_argument("--model", default="models/isoforest.joblib")
    b.add_argument("--no-model", action="store_true", help="explicit ML-off run (rule + physics only)")
    b.add_argument("--allow-unverified-model", action="store_true",
                   help="use a model whose SHA-256 differs from models/MODELS.sha256 (e.g. `aegis train` output)")
    b.add_argument("--no-figures", action="store_true")
    b.set_defaults(func=_cmd_benchmark)

    t = sub.add_parser("train", help="train the anomaly model")
    t.add_argument("--sessions", type=int, default=24)
    t.add_argument("--out", default="models/isoforest.joblib")
    t.add_argument("--seed", type=int, default=100)
    t.set_defaults(func=_cmd_train)

    sv = sub.add_parser("serve", help="start the FastAPI backend (dashboard API + WebSocket)")
    sv.add_argument("--host", default="127.0.0.1")
    sv.add_argument("--port", type=int, default=8000)
    sv.add_argument("--reload", action="store_true", help="SIM only")
    sv.add_argument("--source", choices=["sim", "replay", "serial", "udp"], default="sim",
                    help="telemetry source, fixed for the server's lifetime (default: sim)")
    sv.add_argument("--serial-port", default=None, help="serial: COM7, /dev/ttyAMA0 (receive-only)")
    sv.add_argument("--baud", type=int, default=115200, help="serial: must match the link (115200 on COM7)")
    sv.add_argument("--allow-url", action="store_true", help="serial: allow a socket:// virtual port (REPLAY)")
    sv.add_argument("--no-reconnect", action="store_true",
                    help="serial: a port that cannot be opened is a source error instead of being retried")
    sv.add_argument("--tlog", default=None, help="replay: repo-framed .tlog to replay")
    sv.add_argument("--replay-speed", type=float, default=1.0, help="replay: 1.0 = capture time")
    sv.add_argument("--udp-port", type=int, default=None, help="udp: listen on 127.0.0.1:<port>, passive")
    sv.add_argument("--config-dir", default=None, help="detector profile dir (default: Stage-1 configs/)")
    sv.add_argument("--db", default=None, help="event store (default: artifacts/aegisflight_live.sqlite)")
    sv.add_argument("--gcs-notify", action="store_true",
                    help="broadcast MAVLink STATUSTEXT alert notifications to GCS (UDP target; also onto a UDP or "
                         "socket:// link, never onto a serial device)")
    sv.add_argument("--gcs-notify-host", default="127.0.0.1",
                    help="target GCS host for UDP STATUSTEXT alerts (default: 127.0.0.1)")
    sv.add_argument("--gcs-notify-port", type=int, default=14550,
                    help="target GCS UDP port for STATUSTEXT alerts (default: 14550)")
    sv.add_argument("--defense-mode", choices=["passive", "advisory", "active-ips"], default="passive",
                    help="defense engine posture: passive (IDS only, zero bytes sent), advisory (GCS alerts), active-ips "
                         "(autonomous mitigation; refused on a serial device, which is receive-only)")
    sv.add_argument("--signing-key-file", default=None,
                    help="32-byte MAVLink-2 key (raw or 64 hex chars) used to authenticate the ips-bridge cross-end summary")
    sv.add_argument("--mgmt-key-file", default=None,
                    help="32-byte MANAGEMENT key (separate from the flight key): enables sending the signed in-band "
                         "posture command to the ips-bridge over the radio (live serial/udp source only)")
    sv.set_defaults(func=_cmd_serve)

    ib = sub.add_parser("ips-bridge", help="inline IPS between a flight controller port and a GCS/radio port")
    ib.add_argument("--fc-port", required=True, help="serial port wired to the flight controller (e.g. /dev/ttyAMA0)")
    ib.add_argument("--fc-baud", type=int, default=921600)
    ib.add_argument("--gcs-port", required=True, help="serial port wired to the GCS radio (e.g. /dev/ttyUSB0)")
    ib.add_argument("--gcs-baud", type=int, default=57600)
    ib.add_argument("--allow-url", action="store_true", help="allow socket:// virtual ports (tests, SITL)")
    ib.add_argument("--defense-mode", choices=["passive", "advisory", "active-ips"], default="passive",
                    help="passive/advisory never drop or alter a forwarded frame (except the uplink control frames "
                         "dropped by --vehicle-uplink-filter) and originate nothing toward the FC; by default the bridge "
                         "still sends AEGIS alerts/status and the cross-end summary to the GCS side and consumes "
                         "MAV_CMD_USER_1 COMMAND_LONGs addressed to component 191 (see --gcs-alerts, "
                         "--mgmt-status-interval, --crossend-interval); active-ips filters and counter-acts "
                         "(refused when --fc-port is a serial device: a physical FC is receive-only)")
    ib.add_argument("--vehicle-uplink-filter", action="store_true",
                    help="drop forged / unsigned / replayed / wrong-key control frames from the GCS side before the flight controller, usable on a serial vehicle link (the downlink is never changed and no counter-command is ever sent). Needs --signing-key-file; not combinable with active-ips; fixed for the run (no status-API or radio switch). See docs/VEHICLE_UPLINK_FILTER.md")
    ib.add_argument("--filter-override-file", default=None,
                    help="with --vehicle-uplink-filter: LOCAL off switch. While this file exists on the bridge's disk the filter only reports; "
                         "remove it and the filter re-proves the key before it drops anything again. Not reachable over the radio or the status API")
    ib.add_argument("--filter-lockout-failopen-s", type=float, default=None,
                    help="with --vehicle-uplink-filter, OPTIONAL watchdog (default off): if control frames from a trusted sysid keep failing "
                         "the signature check and no validly signed ground-station frame was seen for this many seconds, forward everything "
                         "until one is seen. Cannot tell a lock-out from an attacker spoofing the pilot's sysid while the real GCS is silent")
    ib.add_argument("--trusted-sysid", type=int, action="append",
                    help="ground-station sysid allowed to command the vehicle (repeatable; default from detector.yaml)")
    ib.add_argument("--signing-key-file", default=None,
                    help="32-byte MAVLink-2 signing key (raw, or 64 hex chars). With it, control traffic must be validly "
                         "signed with an increasing timestamp; counter-frames are signed too")
    ib.add_argument("--signing-permissive", action="store_true",
                    help="rollout only: let UNSIGNED control frames from a trusted sysid through (forged or replayed "
                         "signed frames are still dropped)")
    ib.add_argument("--signing-max-age-s", type=float, default=None,
                    help="also reject signed frames older than this on the bridge clock (needs a correct clock)")
    ib.add_argument("--signing-state", default=None,
                    help="file that keeps the last timestamp per stream across restarts (closes the post-restart replay window)")
    ib.add_argument("--ekf-secondary", action="store_true",
                    help="declare that the aircraft has a configured non-GPS EKF source set; only then may active-ips "
                         "send the EKF source switch (default off: GPS faults escalate to ALT_HOLD instead)")
    ib.add_argument("--firmware-dir", default=None,
                    help="directory of REAL firmware/config *.bin files with a trusted manifest (create it with `aegis fw-manifest DIR`); "
                         "re-hashed every --firmware-recheck-s and a mismatch raises a firmware-integrity alert. Default: not checked")
    ib.add_argument("--firmware-recheck-s", type=float, default=30.0,
                    help="seconds between firmware re-hash passes (hashing cost grows with the size of the files)")
    ib.add_argument("--crossend-interval", type=float, default=1.0,
                    help="seconds between cross-end summaries of the last forwarded GLOBAL_POSITION_INT sent to the GCS "
                         "side only (0 = off); lets a GCS-side 'aegis serve' detect telemetry altered after the bridge")
    ib.add_argument("--contested-policy", choices=["alert", "drop-sensitive"], default="alert",
                    help="unsigned link, two transmitters on one sysid: alert = STATUSTEXT only; drop-sensitive = also drop "
                         "sensitive/control frames from that source in flight (can block the real pilot; forced disarm passes)")
    ib.add_argument("--replay-memory", type=int, default=4096,
                    help="unsigned link: number of forwarded sensitive frames remembered for the byte-identical replay filter")
    ib.add_argument("--gcs-alerts", choices=["on", "off"], default="on",
                    help="send IDS alerts / IPS actions as short AEGIS: STATUSTEXTs to the GCS side (never the FC)")
    ib.add_argument("--mgmt-enable", action="store_true",
                    help="in PASSIVE posture, opt in to in-band GCS management TX/RX and cross-end summaries (default off = 0B TX)")
    ib.add_argument("--alert-min-interval", type=float, default=2.0,
                    help="at most one alert STATUSTEXT per attack type per this many seconds (escalations bypass)")
    ib.add_argument("--mgmt-status-interval", type=float, default=2.0,
                    help="seconds between compact status MEMORY_VECTs to the GCS side (0 = off)")
    ib.add_argument("--mgmt-max-bytes-per-s", type=float, default=150.0,
                    help="byte budget for ALL management traffic (alerts, actions, status, ACKs)")
    ib.add_argument("--mgmt-key-file", default=None,
                    help="32-byte MANAGEMENT key (raw or 64 hex), independent of the flight key; none = remote control disabled")
    ib.add_argument("--mgmt-state", default=None,
                    help="persisted anti-replay state of the management channel (required with --mgmt-key-file)")
    ib.add_argument("--mgmt-max-age-s", type=float, default=300.0,
                    help="ignore a signed management command older than this vs the bridge's wall clock (applied only "
                         "while the clock is set; 0 = off)")
    ib.add_argument("--lock-posture-file", default=None,
                    help="while this file exists remote commands can only RAISE the posture (local override)")
    ib.add_argument("--audit-log", default=None, help="hash-chained JSONL audit log of management commands")
    ib.add_argument("--run-dir", default=None,
                    help="evidence run: archive both directions' raw frames, decisions, actions and run_manifest.json "
                         "here (refuses a dirty tree unless --allow-dirty; the run is then stamped NOT-REPRODUCIBLE)")
    ib.add_argument("--allow-dirty", action="store_true", help="with --run-dir: run on a dirty tree, stamped NOT-REPRODUCIBLE")
    ib.add_argument("--config-dir", default=None)
    ib.add_argument("--model", default=None,
                    help="optional path to hash-verified Isolation Forest model (.joblib) for ML anomaly detection "
                         "(live/SITL drift evidence pending)")
    ib.add_argument("--allow-unverified-model", action="store_true",
                    help="allow loading a model not listed in MODELS.sha256 (unsafe; local dev only, "
                         "live/SITL drift evidence pending)")
    ib.add_argument("--db", default=None, help="log alerts to this SQLite hash-chain store")
    ib.add_argument("--seconds", type=float, default=None, help="run time (default: until Ctrl-C)")
    ib.add_argument("--status-interval", type=float, default=5.0)
    ib.add_argument("--status-port", type=int, default=0,
                    help="serve GET /status (bridge state as JSON) on 127.0.0.1:PORT, read-only (default: off)")
    ib.add_argument("--allow-unsigned", action="store_true",
                    help="acknowledge that active-ips without --signing-key-file cannot stop a counter-tracking forger")
    ib.add_argument("--control-token-file", default=None,
                    help="file holding a token; enables remote posture control (POST /posture) on the status API")
    ib.add_argument("--status-host", default="127.0.0.1",
                    help="bind address of the status API (default 127.0.0.1; non-loopback needs --control-token-file)")
    ib.set_defaults(func=_cmd_ips_bridge)

    fm = sub.add_parser("fw-manifest", help="hash the *.bin files of a directory into its trusted manifest.json")
    fm.add_argument("dir", help="directory holding the firmware / config images to protect")
    fm.set_defaults(func=_cmd_fw_manifest)
    v = sub.add_parser("verify-log", help="verify a SQLite event-log hash chain")
    v.add_argument("db", help="path to the SQLite event log")
    v.add_argument("--anchors", default=None, help="verify against an external <db>.anchors.jsonl file")
    v.add_argument("--verify-actions", action="store_true", help="also verify the actions table hash chain")
    v.set_defaults(func=_cmd_verify_log)

    ver = sub.add_parser("version", help="print version")
    ver.set_defaults(func=lambda a: (print(f"aegisflight {__version__}"), 0)[1])

    ob = sub.add_parser("onboard", help="run unified onboard companion runtime from a YAML config")
    ob.add_argument("--config", default=None, help="YAML config path (default: safe passive serial config)")
    ob.add_argument("--seconds", type=float, default=None, help="optional timed exit (default: until SIGTERM/SIGINT)")
    ob.add_argument("--topology", choices=["inline", "side-tap"], default=None,
                    help="override wiring topology (inline bridge or single-port receive-only side-tap)")
    ob.add_argument("--defense-mode", choices=["passive", "advisory", "active-ips"], default=None,
                    help="override configured defense posture")
    ob.add_argument("--run-dir", default=None, help="override run_root for SQLite/archive output")
    ob.add_argument("--allow-url", action="store_true", help="override allow_url=true for socket:// tests")
    ob.add_argument("--preflight", action="store_true", help="run 0-TX onboard preflight diagnostics and exit")
    ob.add_argument("--enroll-firmware", default=None, metavar="OUT_YAML",
                    help="passively listen for AUTOPILOT_VERSION (0 B TX) and pin firmware allowlist YAML")
    ob.add_argument("--vehicle-name", default="companion-fc", help="vehicle entry name used with --enroll-firmware")
    ob.add_argument("--enroll-timeout", type=float, default=10.0, help="seconds to wait for AUTOPILOT_VERSION")
    ob.set_defaults(func=_cmd_onboard)

    er = sub.add_parser("export-report", help="export cryptographically verified forensic flight report")
    er.add_argument("--db", required=True, help="path to events.sqlite")
    er.add_argument("--out", default=None, help="output path (.json or .html; default: stdout JSON)")
    er.add_argument("--format", choices=["json", "html"], default="json", help="output format")
    er.add_argument("--run-id", default=None, help="optional single run_id to verify/export")
    er.add_argument("--anchors", default=None, help="optional external .anchors.jsonl path")
    er.add_argument("--no-actions", action="store_true", help="skip actions hash-chain verification")
    er.set_defaults(func=_cmd_export_report)

    fd = sub.add_parser("field-drill", help="run zero-TX shadow verification drills against IPS/detectors")
    fd.add_argument("--scenario", default="all", help="drill scenario name or 'all'")
    fd.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    fd.set_defaults(func=_cmd_field_drill)

    return p


def _cmd_export_report(args: argparse.Namespace) -> int:
    import json

    from ..reporting.forensic_report import build_forensic_report, render_forensic_html

    try:
        rep = build_forensic_report(
            args.db,
            run_id=args.run_id,
            anchors_path=args.anchors,
            verify_actions=not args.no_actions,
        )
    except (OSError, ValueError) as exc:
        print(f"aegis export-report: {exc}", file=sys.stderr)
        return 2
    out_text = render_forensic_html(rep) if args.format == "html" else json.dumps(rep, indent=2)
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(out_text, encoding="utf-8")
        print(f"Wrote forensic {args.format.upper()} report -> {args.out} (verified={rep['verified']})")
    else:
        print(out_text)
    return 0 if rep["verified"] else 1


def _cmd_field_drill(args: argparse.Namespace) -> int:
    import json

    from ..testing.field_drill import run_field_drill

    try:
        res = run_field_drill(args.scenario)
    except ValueError as exc:
        print(f"aegis field-drill: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(res, indent=2))
    else:
        for sc in res["scenarios"]:
            badge = "PASS" if sc["ok"] else "FAIL"
            print(f"[{badge}] {sc['name']} (0B FC TX, {sc['elapsed_ms']} ms)")
        print(f"Field drill summary: {res['passed']}/{res['total']} passed (zero_real_fc_tx={res['zero_real_fc_tx']})")
    return 0 if res["ok"] else 1


def _cmd_onboard(args: argparse.Namespace) -> int:
    import json

    from ..onboard import load_onboard_config, run_enroll_firmware, run_onboard, run_preflight

    try:
        cfg = load_onboard_config(args.config)
    except (OSError, ValueError) as exc:
        print(f"aegis onboard: bad --config: {exc}", file=sys.stderr)
        return 2
    if args.topology is not None:
        cfg.topology = args.topology
    if args.defense_mode is not None:
        cfg.defense_mode = args.defense_mode
    if args.run_dir is not None:
        cfg.run_root = args.run_dir
    if args.allow_url:
        cfg.allow_url = True
    if args.preflight:
        report = run_preflight(cfg)
        print(json.dumps(report, indent=2))
        return 0 if report["ok"] else 2
    if args.enroll_firmware:
        return run_enroll_firmware(
            cfg,
            out_path=args.enroll_firmware,
            vehicle_name=args.vehicle_name,
            timeout_s=args.enroll_timeout,
        )
    return run_onboard(cfg, seconds=args.seconds)


def main(argv: list[str] | None = None) -> int:
    # Evidence strings use unicode (≥, °, ²); ensure the console can print them
    # on Windows (cp1252 default) without crashing.
    for stream in (sys.stdout, sys.stderr):
        with contextlib.suppress(Exception):
            stream.reconfigure(encoding="utf-8")
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
