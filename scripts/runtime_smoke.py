#!/usr/bin/env python3
"""Bounded real-socket smoke test; saves ONLY this test's loopback records."""
import argparse
import collections
import hashlib
import http.client
import http.server
import json
import multiprocessing as mp
import os
from pathlib import Path
import signal
import socket
import statistics
import struct
import subprocess
import sys
import threading
import time

ROOT = None
BINARY = None
DNS_ADDRESS = "127.0.0.88"


def http_server(pipe):
    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        def log_message(self, *args):
            pass
        def do_GET(self):
            time.sleep(0.12 if self.path.startswith("/slow") else 0.02)
            body = b"controlled-loopback-fixture\n"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    pipe.send(server.server_port)
    server.serve_forever()


def dns_server(pipe):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind((DNS_ADDRESS, 53))
    except OSError as exc:
        pipe.send({"error": str(exc)})
        return
    pipe.send(53)
    while True:
        data, peer = sock.recvfrom(512)
        if b"silent" in data:
            continue
        time.sleep(0.03)
        # A controlled DNS NOERROR response with the original question, no answer.
        sock.sendto(data[:2] + b"\x81\x80" + data[4:], peer)


def bpftool(kind):
    return json.loads(subprocess.check_output(["bpftool", kind, "show", "-j"], text=True, timeout=5))


def request(port, path):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
    started = time.perf_counter_ns()
    try:
        connection.request("GET", path)
        response = connection.getresponse()
        response.read()
        if response.status != 200:
            raise RuntimeError("fixture HTTP failure")
        return (time.perf_counter_ns() - started) / 1000
    finally:
        connection.close()


def dns_query(transaction_id, label):
    wire = struct.pack("!HHHHHH", transaction_id, 0x0100, 1, 0, 0, 0)
    for part in (label, "test"):
        encoded = part.encode("ascii")
        wire += bytes([len(encoded)]) + encoded
    return wire + b"\x00\x00\x01\x00\x01"


def main():
    global ROOT, BINARY
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path, help="locally built Linux collector")
    parser.add_argument("--output-dir", required=True, type=Path, help="NEW private evidence directory")
    args = parser.parse_args()
    if sys.platform != "linux" or os.geteuid() != 0:
        parser.error("run on a test Linux host as root in a new network namespace")
    if Path("/proc/self/ns/net").stat().st_ino == Path("/proc/1/ns/net").stat().st_ino:
        parser.error("refusing the host network namespace; use unshare --net and bring its lo up")
    BINARY = args.binary.resolve()
    if not BINARY.is_file() or not os.access(BINARY, os.X_OK):
        parser.error("--binary must be an existing executable")
    os.umask(0o077)
    before = {p["id"] for p in bpftool("prog")}
    before_links = {p["id"] for p in bpftool("link")}
    ROOT = args.output_dir.resolve()
    ROOT.mkdir(mode=0o700, parents=True, exist_ok=False)
    children = []
    collector = None
    records = []
    summary = {"kernel": os.uname().release, "binary_sha256": hashlib.sha256(BINARY.read_bytes()).hexdigest()}
    try:
        read_http, write_http = mp.Pipe(False)
        server = mp.Process(target=http_server, args=(write_http,), daemon=True)
        server.start(); children.append(server)
        if not read_http.poll(5):
            raise RuntimeError("HTTP fixture did not become ready")
        port = read_http.recv()
        read_dns, write_dns = mp.Pipe(False)
        server = mp.Process(target=dns_server, args=(write_dns,), daemon=True)
        server.start(); children.append(server)
        if not read_dns.poll(5):
            raise RuntimeError("DNS fixture did not become ready")
        dns_ready = read_dns.recv()
        if isinstance(dns_ready, dict):
            raise RuntimeError(dns_ready["error"])
        parent_pid = os.getpid()
        fixture_pids = {parent_pid, children[0].pid}
        baseline = {kind: [request(port, f"/{kind}/baseline-{i}") for i in range(8)] for kind in ("fast", "slow")}
        errors_path = ROOT / "runtime-probe.stderr"
        with errors_path.open("w") as errors_file:
            collector = subprocess.Popen([
                str(BINARY), "-source=ebpf", "-node-name=hermes-loopback-validation",
                "-output-mode=windows", "-window=5s", "-duration=12s", "-conntrack=false",
            ], stdout=subprocess.PIPE, stderr=errors_file, text=True, bufsize=1, start_new_session=True)
            def consume():
                for line in collector.stdout:
                    record = json.loads(line)
                    schema = record.get("schemaVersion", "")
                    flow = record.get("flow", {})
                    endpoints = (flow.get("source", {}), flow.get("destination", {}))
                    ours = False
                    if schema == "network.flow/v1alpha1":
                        ours = any(e.get("address") == "127.0.0.1" and e.get("port") == port for e in endpoints) and record.get("process", {}).get("pid") in fixture_pids
                    elif schema == "network.l7/v1alpha1":
                        ours = record.get("observerPid") == parent_pid and any(e.get("port") == port for e in endpoints)
                    elif schema == "network.dns/v1alpha1":
                        ours = record.get("observerPid") == parent_pid and record.get("server", {}).get("address") == DNS_ADDRESS
                    elif "drop/" in schema:
                        # Coverage counters contain no plaintext; preserve to disclose losses.
                        ours = True
                    if ours:
                        records.append(record)
            consumer = threading.Thread(target=consume, daemon=True)
            consumer.start()
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                if collector.poll() is not None:
                    raise RuntimeError("collector exited during attach")
                live_links = {p["id"] for p in bpftool("link")}
                if live_links - before_links:
                    break
                time.sleep(0.05)
            else:
                raise RuntimeError("no attached BPF links observed")
            active = {}
            for i in range(32):
                kind = "fast" if i % 2 == 0 else "slow"
                path = f"/{kind}/{i}"
                active[path] = request(port, path)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                client.settimeout(2)
                for i in range(2):
                    client.sendto(dns_query(i + 1, "answer"), (DNS_ADDRESS, 53))
                    client.recvfrom(512)
                client.sendto(dns_query(3, "silent"), (DNS_ADDRESS, 53))
            summary["collector_exit"] = collector.wait(timeout=18)
            consumer.join(timeout=3)
            if consumer.is_alive():
                raise RuntimeError("collector output did not finish")
        l4 = [r for r in records if r.get("schemaVersion") == "network.flow/v1alpha1"]
        l7 = [r for r in records if r.get("schemaVersion") == "network.l7/v1alpha1"]
        dns_records = [r for r in records if r.get("schemaVersion") == "network.dns/v1alpha1"]
        latency = {kind: [r["responseLatencyMicros"] for r in l7 if r.get("path", "").startswith(f"/{kind}/")] for kind in ("fast", "slow")}
        outcomes = collections.Counter(r["outcome"] for r in dns_records)
        summary.update({
            "http_requests": len(active), "observed_http_transactions": len(l7),
            "l4_windows": len(l4), "complete_l4_windows": sum(not r.get("partial", False) for r in l4),
            "srtt_samples": sum(r.get("rtt", {}).get("count", 0) for r in l4),
            "dns_outcomes": dict(outcomes),
            "baseline_client_median_us": {k: statistics.median(v) for k,v in baseline.items()},
            "active_client_median_us": {k: statistics.median(v for path,v in active.items() if path.startswith(f"/{k}/")) for k in ("fast", "slow")},
            "observed_http_median_us": {k: statistics.median(v) if v else None for k,v in latency.items()},
            "output_types": dict(collections.Counter(r.get("schemaVersion") for r in records)),
            "command_line_leaks": sum("cmdline" in r.get("process", {}) for r in records),
            "collector_stderr": errors_path.read_text(),
        })
        summary["accepted"] = (summary["collector_exit"] == 0 and len(l7) == len(active)
            and summary["srtt_samples"] > 0 and summary["complete_l4_windows"] > 0
            and outcomes["response"] == 2 and outcomes["no_response"] == 1
            and all(latency.values()) and statistics.median(latency["slow"]) > statistics.median(latency["fast"]) + 50000
            and summary["command_line_leaks"] == 0)
    except Exception as exc:
        summary["error"] = str(exc)
        summary["accepted"] = False
    finally:
        if collector is not None and collector.poll() is None:
            os.killpg(collector.pid, signal.SIGTERM)
            try:
                collector.wait(timeout=7)
            except subprocess.TimeoutExpired:
                os.killpg(collector.pid, signal.SIGKILL)
                collector.wait(timeout=3)
        for child in children:
            if child.is_alive():
                child.terminate()
            child.join(timeout=3)
            if child.is_alive():
                child.kill(); child.join(timeout=2)
        after = {p["id"] for p in bpftool("prog")}
        after_links = {p["id"] for p in bpftool("link")}
        summary["residual_program_ids"] = sorted(after - before)
        summary["residual_link_ids"] = sorted(after_links - before_links)
        summary["fixture_processes_stopped"] = all(not c.is_alive() for c in children)
        summary["accepted"] = summary.get("accepted", False) and not summary["residual_program_ids"] and not summary["residual_link_ids"] and summary["fixture_processes_stopped"]
        for name,content in (("runtime-probe.json", json.dumps(summary,indent=2)), ("runtime-probe.jsonl", "".join(json.dumps(r)+"\n" for r in records))):
            path = ROOT / name
            path.write_text(content)
            path.chmod(0o600)  # evidence directory is private, including on failure
        print(json.dumps(summary, indent=2))
    return 0 if summary["accepted"] else 1


if __name__ == "__main__":
    sys.exit(main())
