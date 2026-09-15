#!/usr/bin/env python3
"""Real Linux regression: recvfrom(MSG_ERRQUEUE) must not become DNS traffic."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import threading
import time

from runtime_smoke import bpftool, dns_query


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True, help="NEW private evidence directory")
    args = parser.parse_args()
    if sys.platform != "linux" or os.geteuid() != 0:
        parser.error("requires test Linux root in a new network namespace")
    if Path("/proc/self/ns/net").stat().st_ino == Path("/proc/1/ns/net").stat().st_ino:
        parser.error("refusing the host network namespace; use unshare --net")
    binary = args.binary.resolve()
    if not binary.is_file() or not os.access(binary, os.X_OK):
        parser.error("--binary must be an existing executable")
    os.umask(0o077)
    output = args.output_dir.resolve()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    before = {p["id"] for p in bpftool("prog")}
    before_links = {p["id"] for p in bpftool("link")}
    records, consumer_errors = [], []
    collector = None
    summary = {"kernel": os.uname().release, "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest()}
    try:
        with (output / "collector.stderr").open("w") as errors_file:
            collector = subprocess.Popen([
                str(binary), "-source=ebpf", "-node-name=hermes-errorqueue-validation",
                "-output-mode=windows", "-duration=8s", "-conntrack=false", "-process=false",
            ], stdout=subprocess.PIPE, stderr=errors_file, text=True, start_new_session=True)
            output_stream = collector.stdout
            assert output_stream is not None
            def consume():
                try:
                    for line in output_stream:
                        record = json.loads(line)
                        if (record.get("schemaVersion") == "network.dns/v1alpha1"
                            and record.get("observerPid") == os.getpid()
                            and record.get("queryName") == "errorqueue.test"):
                            records.append(record)
                except Exception as exc:
                    consumer_errors.append(str(exc))
            consumer = threading.Thread(target=consume, daemon=True)
            consumer.start()
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                if collector.poll() is not None:
                    raise RuntimeError("collector exited during attach")
                if {p["id"] for p in bpftool("link")} - before_links:
                    break
                time.sleep(0.05)
            else:
                raise RuntimeError("no collector BPF link observed")
            target = ("127.0.0.89", 53) # no listener in this isolated namespace
            query = dns_query(49001, "errorqueue")
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                client.setsockopt(socket.IPPROTO_IP, 11, 1) # Linux UAPI IP_RECVERR
                client.settimeout(2)
                client.sendto(query, target)
                returned, address = client.recvfrom(512, socket.MSG_ERRQUEUE)
                if returned != query or address != target:
                    raise RuntimeError("error queue did not return the original query/destination")
                summary["error_queue_payload_bytes"] = len(returned)
            summary["collector_exit"] = collector.wait(timeout=15)
            consumer.join(timeout=3)
            if consumer.is_alive() or consumer_errors:
                raise RuntimeError("output reader did not finish cleanly: " + str(consumer_errors))
        summary["dns_records"] = len(records)
        summary["reversed_records"] = sum(r.get("client", {}).get("address") == target[0] for r in records)
        summary["accepted"] = (summary["collector_exit"] == 0 and len(records) == 1
            and records[0].get("server", {}).get("address") == target[0]
            and records[0].get("outcome") == "no_response" and summary["reversed_records"] == 0)
        summary["collector_stderr"] = (output / "collector.stderr").read_text()
    except Exception as exc:
        summary.update(error=str(exc), accepted=False)
    finally:
        if collector is not None and collector.poll() is None:
            os.killpg(collector.pid, signal.SIGTERM)
            try:
                collector.wait(timeout=7)
            except subprocess.TimeoutExpired:
                os.killpg(collector.pid, signal.SIGKILL)
                collector.wait(timeout=3)
        summary["residual_program_ids"] = sorted({p["id"] for p in bpftool("prog")} - before)
        summary["residual_link_ids"] = sorted({p["id"] for p in bpftool("link")} - before_links)
        summary["accepted"] = summary.get("accepted", False) and not summary["residual_program_ids"] and not summary["residual_link_ids"]
        (output / "dns-errorqueue.json").write_text(json.dumps(summary, indent=2))
        (output / "dns-errorqueue.jsonl").write_text("".join(json.dumps(r) + "\n" for r in records))
        print(json.dumps(summary, indent=2))
    return 0 if summary["accepted"] else 1


if __name__ == "__main__":
    sys.exit(main())
