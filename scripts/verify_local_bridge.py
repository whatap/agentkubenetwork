#!/usr/bin/env python3
"""Build and verify the local Go/JVM bridge; never boot an agent or send to a backend."""
import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import xml.etree.ElementTree as ET

TESTS = [
    'NetworkEdgeConfigurationTest', 'NetworkEdgeCoreTest', 'NetworkEdgeServerTest',
    'NetworkEdgeServerDeadlineTest',
    'NetworkEdgeFeatureTest', 'NetworkEdgeStartupTest', 'NetworkEdgeInteropIT',
    'QueueAcceptanceTest', 'NetworkEdgeQueueAcceptanceTest',
    'OfflineSendBufferTest',
]
COLUMNS = [
    'time', 'category', 'tag:schema', 'tag:observer_node', 'tag:protocol',
    'tag:src_addr', 'field:src_port', 'tag:dst_addr', 'field:dst_port', 'tag:observer_role',
    'tag:observer_container_id', 'tag:src_resolved_addr', 'field:src_resolved_port',
    'tag:src_resolution_via', 'tag:dst_resolved_addr', 'field:dst_resolved_port',
    'tag:dst_resolution_via', 'field:window_start_ms', 'field:window_end_ms',
    'field:srtt_count', 'field:srtt_sum_us', 'field:srtt_min_us', 'field:srtt_max_us',
]


def millis(text):
    stamp = datetime.fromisoformat(text.replace('Z', '+00:00'))
    delta = stamp - datetime(1970, 1, 1, tzinfo=timezone.utc)
    return (delta.days * 86400 + delta.seconds) * 1000 + delta.microseconds // 1000


def expected_row(window):
    flow, rtt = window['flow'], window['rtt']
    start, end = millis(window['windowStart']), millis(window['windowEnd'])
    values = {
        'time': start, 'category': 'kube_network_edge_v1alpha1',
        'tag:schema': 'network.edge.window/v1alpha1', 'tag:observer_node': flow['nodeName'],
        'tag:protocol': 'tcp', 'tag:src_addr': flow['source']['address'],
        'field:src_port': flow['source']['port'], 'tag:dst_addr': flow['destination']['address'],
        'field:dst_port': flow['destination']['port'],
        'tag:observer_role': {'egress': 'source', 'ingress': 'destination'}.get(flow['direction'], 'unknown'),
        'field:window_start_ms': start, 'field:window_end_ms': end,
        'field:srtt_count': rtt['count'], 'field:srtt_sum_us': rtt['sumMicros'],
        'field:srtt_min_us': rtt['minMicros'], 'field:srtt_max_us': rtt['maxMicros'],
    }
    process = window.get('process') or {}
    if process.get('containerId'):
        values['tag:observer_container_id'] = process['containerId']
    for name, prefix in [('sourceResolved', 'src'), ('destinationResolved', 'dst')]:
        resolved = window.get(name)
        if resolved:
            values['tag:' + prefix + '_resolved_addr'] = resolved['address']
            values['field:' + prefix + '_resolved_port'] = resolved['port']
            values['tag:' + prefix + '_resolution_via'] = resolved['via']
    cells = [str(values.get(column, '')) for column in COLUMNS]
    if any('\t' in cell or '\n' in cell or '\r' in cell for cell in cells):
        raise ValueError('manifest values must not contain control separators')
    return '\t'.join(cells)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--java-repo', type=Path, required=True)
    parser.add_argument('--maven', type=Path, required=True)
    parser.add_argument('--go', type=Path, required=True)
    parser.add_argument('--input', type=Path, required=True, help='captured JSONL, not pretty JSON')
    parser.add_argument('--node', required=True, help='explicit trusted fixture node; must match all selected windows')
    parser.add_argument('--output-dir', type=Path, required=True, help='new directory for logs and evidence')
    args = parser.parse_args()
    java, maven, go, source, output = [x.resolve() for x in
        (args.java_repo, args.maven, args.go, args.input, args.output_dir)]
    for path in (maven, go, source):
        if not path.is_file():
            parser.error('missing file: ' + str(path))
    if not (java / 'whatap.kube.node/pom.xml').is_file():
        parser.error('java-repo is not the agentkubejava reactor')
    output.mkdir(parents=True, mode=0o700, exist_ok=False)
    project = Path(__file__).resolve().parents[1]
    windows = []
    for line in source.read_text().splitlines():
        if len(line.encode()) > 1024 * 1024:
            raise ValueError('input record exceeds 1 MiB')
        if not line.strip():
            continue
        record = json.loads(line)
        if record.get('schemaVersion') == 'network.flow/v1alpha1' and not record.get('partial', False) and record['rtt']['count'] > 0:
            if record['flow']['nodeName'] != args.node:
                raise ValueError('fixture node does not match explicitly configured --node')
            windows.append(record)
    if not windows:
        raise ValueError('no completed, measured L4 windows in input')
    input_path, manifest = output / 'input.jsonl', output / 'expected.tsv'
    capture = output / 'java-actual.tsv'
    input_path.write_text(''.join(json.dumps(x, separators=(',', ':')) + '\n' for x in windows))
    manifest.write_text('\t'.join(COLUMNS) + '\n' + '\n'.join(expected_row(x) for x in windows) + '\n')

    def run(command, cwd, log, timeout):
        result = subprocess.run(command, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=timeout)
        (output / log).write_text(result.stdout)
        if result.returncode:
            raise RuntimeError('command failed; see ' + str(output / log))

    binary = output / 'network-edge-submit'
    collector_binary = output / 'agentkubenetwork'
    run([str(go), 'test', '-race', '-count=1', './...'], project, 'go-tests.log', 180)
    run(['make', 'build', 'GO=' + str(go), 'BIN_DIR=' + str(output)], project, 'go-build.log', 120)
    if not binary.is_file() or not collector_binary.is_file():
        raise AssertionError('make build must produce both the collector and TagCount sender in BIN_DIR')
    command = [str(maven), '-q', '-o', '-pl', 'whatap.kube.node', '-am', '-Dtest=' + ','.join(TESTS),
        '-Dsurefire.failIfNoSpecifiedTests=false', '-Dnetwork.edge.go.binary=' + str(binary),
        '-Dnetwork.edge.input=' + str(input_path), '-Dnetwork.edge.manifest=' + str(manifest),
        '-Dnetwork.edge.capture=' + str(capture), '-Dnetwork.edge.node=' + args.node,
        '-Dnetwork.edge.expected=' + str(len(windows)), 'test']
    run(command, java, 'java-tests.log', 180)
    if Counter(manifest.read_text().splitlines()) != Counter(capture.read_text().splitlines()):
        raise AssertionError('Java output differs from the source manifest')
    suites = {}
    for file in (java / 'whatap.kube.node/target/surefire-reports').glob('TEST-*.xml'):
        suite = ET.parse(file).getroot()
        name = suite.attrib['name'].rsplit('.', 1)[-1]
        if name not in TESTS:
            continue
        counts = {key: int(suite.attrib.get(key, '0')) for key in ('tests', 'failures', 'errors', 'skipped')}
        if counts['tests'] != len(suite.findall('testcase')) or any(counts[x] for x in ('failures', 'errors', 'skipped')):
            raise AssertionError('invalid or failing test report: ' + name)
        suites[name] = counts
    if set(suites) != set(TESTS):
        raise AssertionError('missing expected test suites')
    summary = {'verified': True, 'input_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
        'go_binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
        'collector_binary_sha256': hashlib.sha256(collector_binary.read_bytes()).hexdigest(),
        'windows_matched': len(windows), 'java_tests': sum(x['tests'] for x in suites.values()),
        'suites': suites, 'backend_writes': False, 'agent_deployment': False,
        'note': 'Real Go/JVM TCP and official pack serialization; integration sink is a local test capture. Queue tests use unstarted real queues.'}
    (output / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps(summary, indent=2))


if __name__ == '__main__':
    main()
