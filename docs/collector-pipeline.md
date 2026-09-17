# 수집 파이프라인과 운영 적용 경계

## 먼저 구분할 것

이 저장소는 실제 커널 이벤트를 수집한다. 하지만 **수집기 JSONL 출력**, **TCP 전송**, **WhaTap 저장·조회**, **고객 운영 준비**는 서로 다른 완료 조건이다. 이 문서는 수집기의 현재 계약과 아직 검증되지 않은 경계를 설명한다.

```text
Linux 커널 / 지원 OpenSSL 함수
  └─ eBPF → ring buffer → EventReader
       └─ internal/app/events.go
            ├─ TCP → Observation → 대상정보 보강 / 제한된 재시도
            │                     └─ 선택: Stream → per-flow Window
            │                            └─ 선택: Go TagCount 큐 → WhaTap TCP 직접 전송
            ├─ HTTP → 보강정보 snapshot → L7 correlator
            ├─ DNS  → 보강정보 snapshot → DNS correlator
            └─ coverage/drop
                 └─ bounded output queue → JSONL
                      └─ 대안: 완료된 L4 창 → network-edge-submit → 전용 Java 수신부
                           └─ TagCountPack → 노드 큐 수락까지 로컬 검증
                                └─ [아직 미검증] WhaTap 저장 → 조회 → UI
```

추천 읽기 순서:

1. `cmd/agentkubenetwork/main.go`: 입력 경로, 옵션, 종료.
2. `internal/app/events.go`: 이벤트 종류별 분기와 종료/타이머.
3. `internal/app/pipeline.go`, `internal/flow/stream.go`: 주기 집계.
4. `internal/dns/dns.go`, `internal/l7/correlator.go`: 요청/응답 연결.
5. `internal/collector/bpf/flow.bpf.c`: 어떤 실제 함수/시스템콜을 관측하는가.

## 실행 모드

기본 `-source=stdin`은 입력을 EOF까지 읽고 집계하는 **배치 모드**다. 무한 스트림용 주기 전송기로 사용하면 안 된다.

실수집과 주기 JSONL 출력을 함께 실행하려면:

```bash
sudo ./bin/agentkubenetwork \
  -source=ebpf -node-name=TEST_NODE \
  -output-mode=windows -window=5s -allowed-lateness=1s \
  -max-windows=16384 -output-queue=4096 \
  -output-drain-timeout=5s -duration=30s
```

- `raw`: 관측별 출력. 호환성을 위한 기본값이며, `-window`로 주기 집계를 켜지 않는다.
- `windows`: TCP Observation을 창으로 집계. HTTP/DNS/drop은 각자의 타입 그대로 출력한다.
- `both`: 원시 TCP 관측과 집계 창을 모두 출력한다. 소비자가 둘을 합산하면 중복이다.
- `-duration=0`: 시간 제한 없음. SIGINT/SIGTERM은 정상 종료를 요청한다.
- `-max-events`: 출력 레코드 수가 아니라 reader의 입력 이벤트 수 제한이다.
- 출력 옵션·시간 제한은 `ebpf` 경로용이다. `stdin`은 기존 배치 동작을 유지한다.
- OpenSSL은 `-openssl-library`를 지정한 경우만 부착한다. 라이브러리 경로와 지원 API는 시스템별 검증이 필요하다.

`-export=tagcount`를 추가하면 Java 없이 수집기 내부에서 완료·측정된 L4 창을 직접 전송한다. 기본은 `-export=none`이다. 별도의 제한 큐와 키/서버/객체 설정, 실패 및 종료 계약은 [독립 TagCount 전송](direct-tagcount.md)을 따른다. 기본 `-stdout=auto`는 TagCount 전송 시 JSONL을 끄고, `-stdout=jsonl`로 복원한다. 같은 창을 Java 브리지로도 보내면 중복될 수 있다. stderr의 주기 요약은 `-log-level=info -log-interval=1m`이며 종료 요약/fatal 오류는 끄지 않는다. [로그 설정](logging.md)을 참고한다.

## 창과 식별정보

창은 `[windowStart, windowEnd)`이고, `windowEnd <= now - allowedLateness`일 때만 정상 출력한다. 새 이벤트가 없어도 타이머가 flush한다. 종료 시 아직 완료되지 않은 창은 `partial:true`다. 빈 정상 창이나 가짜 percentile은 만들지 않는다.

집계 키는 원본 FlowKey와 보강정보를 포함한다. unknown과 known, 서로 다른 NAT 대상, PID 세대 또는 컨테이너를 조용히 합치거나 나중 정보로 덮지 않는다.

- `sourceResolved` / `destinationResolved`: 원래 주소 옆에 보존되는 NAT 관측 결과.
- `process`: **관측자**의 PID/startTimeTicks/containerId/Via. 정규화된 Flow의 source를 소유한다는 뜻은 아니다.
- `comm`: 값 차이도 구분해 입력 순서에 따라 이름이 달라지지 않게 한다.
- `cmdline`: Window, HTTP, DNS 출력에서는 제외. 진단용 raw TCP 출력에는 들어갈 수 있으므로 외부 전송·공개 로그에 쓰지 않는다.
- `observationCount`: 입력 관측 수. TCP 연결 수나 SRTT 샘플 수가 아니다.
- `rtt.count` / `jitter.count`: 각 분포의 실제 샘플 수. count가 0이면 측정값이 없는 것이다.

이것은 **소켓 튜플·관측자별 flow 창**이지, Pod/Service별 제품 edge 집계의 완성이 아니다. ephemeral port와 PID를 그대로 backend tag로 보내면 cardinality가 커진다. Kubernetes UID/time-valid identity join과 제품 집계 정책은 별도로 필요하다.

`ObservedAt`은 userspace reader의 wall-clock 관측 시각이다. `KernelTimestampNS`는 별도의 커널 monotonic 시각이다. 현재 창 시간은 커널 시각을 wall time으로 역산한 패킷 도착 시각이 아니며, ring-buffer 지연에 따른 시간 오차는 운영 검증 대상이다.

## DNS의 의미와 범위

- 대기 질의는 기본 5초 후 `no_response`로 출력한다. 뜻은 **응답을 관측하지 못함**이지 DNS 서버 장애의 증명이 아니다.
- 종료 시 아직 만료되지 않은 질의는 `incomplete`, `reason:capture_ended`다.
- 대기는 기본 16,384건으로 제한한다. 용량 초과는 `incomplete/state_capacity`로 구분한다.
- heap으로 만료 대상을 관리한다. 매 이벤트마다 대기 맵 전체를 훑지 않으며, 제거한 항목을 무한한 tombstone으로 남기지 않는다.
- 상관 키는 질의 ID/name/type, endpoint, node와 observer PID를 구분한다. 동일한 pending key의 반복 질의는 첫 질의 기준으로 처리한다.
- 실제 IPv4 `sendto/recvfrom` 비연결 UDP는 수신의 반환 sockaddr를 읽어 연결한다. 읽기는 성공한 syscall 이후, 최초 버퍼 용량과 반환 길이 안으로 제한한다.
- wildcard socket의 `client.address=0.0.0.0`은 로컬 주소가 특정되지 않은 소켓 상태다. 실제 Pod IP로 해석하지 않는다.
- 비연결 IPv6, 모든 recvmsg/recvmmsg 경로, DNS-over-TCP/TLS/HTTPS 전체 지원을 주장하지 않는다. 유실·미지원 경로가 있으면 `no_response` 해석에 coverage를 함께 봐야 한다.

## 측정 의미

- TCP SRTT는 ACK 기반 평활 RTT다. HTTP 처리시간이 아니다.
- HTTP/1의 현재 캡처/파싱은 요청 첫 줄과 응답 상태줄 중심이다. 전체 응답 헤더 블록 완료 또는 본문 완료의 정확한 시각을 보장하지 않는다.
- HTTP/2는 요청과 최종 응답 헤더를 stream ID로 연결한다. gRPC trailers/RPC 완료 지연이 아니다.
- 지원 OpenSSL 함수의 평문 버퍼를 관찰한다. TLS 패킷을 복호화하거나 모든 언어 런타임의 TLS를 지원하는 방식이 아니다.
- bytes/packets/retransmission/loss 등 아직 수집하지 않는 숫자 필드의 0을 정상 관측값으로 시각화하면 안 된다.

## 정체와 손실

Go 처리 루프와 JSON writer 사이에는 건수 제한 큐가 있다. writer 정체가 곧바로 reader 진행을 막지 않으며, 큐가 차면 출력 레코드 누락을 계수해 보고한다. 출력 장치가 영구적으로 실패하면 그 장치로 누락 보고까지 전달할 수는 없다. 최종 drain 실패는 오류로 반환된다.

커널 ring-buffer reserve 실패는 telemetry drop으로 기록하고 반환한다. 고객 요청이 Go 출력 큐를 직접 기다리는 구조는 아니다. 다만 eBPF 실행 비용, CPU/메모리 경합과 실제 손실률은 별도 부하 검증이 필요하다. **건수 상한이 있다는 사실만으로 안전한 메모리 사용량이 입증되지는 않는다.**

## 재현 가능한 Linux smoke

필요 도구: Linux/BTF/fentry, clang, Go, Python 3, `bpftool`, `ip`, `unshare`, 테스트 호스트의 root 권한. 기존 서비스가 실행되는 호스트에서 임의로 권한·DNS 설정을 바꾸지 않는다.

```bash
make generate-ebpf
make check
go test -race -count=1 ./...

sudo unshare --net -- sh -c '
  ip link set dev lo up
  exec python3 scripts/runtime_smoke.py \
    --binary bin/agentkubenetwork \
    --output-dir /tmp/agentkubenetwork-proof-UNIQUE
'
```

출력 디렉터리는 새 경로여야 하며 기존 파일을 덮지 않는다. 스크립트는 호스트의 기본 network namespace에서 실행하는 것을 거절한다. **커널 추적 프로그램은 node 범위이므로**, 별도 network namespace가 BPF 관측 범위 자체를 제한하는 것은 아니다. 저장하는 JSONL은 시험 endpoint/PID와 비평문 drop 정보로 필터링한다.

시험은 제어된 HTTP 지연과 실제 UDP DNS 송수신/무응답을 발생시킨다. JSON 증거에는 입력/관측 수, 지연, 창, 샘플 수, 바이너리 SHA256, 종료 후 BPF program/link 잔존 및 시험 프로세스 정리 여부가 들어간다. 이는 소규모 실제 소켓 검증이지 고객 부하 benchmark가 아니다.

## 서버 연동의 다음 경계

완료된 L4 창은 `kube_network_edge_v1alpha1` TagCountPack으로 전송한다. 기본적으로 전송은 꺼져 있으며, 활성화 경로는 두 가지다.

- [독립 Go 전송](direct-tagcount.md): 수집기 내부에서 팩 생성·제한 큐·키 협상·TCP 전송. 프로젝트와 객체는 Go의 명시적 설정에서 결정한다.
- [선택적 Java 브리지](local-node-bridge.md): JSONL을 `network-edge-submit`이 `uploadNetworkEdge` 전용 명령으로 넘긴다. 프로젝트와 객체는 Java 설정에서 결정한다.

일반 `uploadTagCount`를 무제한 호출하거나 namespace 프로젝트 전체에 방송하지 않는다. 직접 전송의 TCP 쓰기 완료, Java의 Local ACK, backend 저장, API 조회는 각각 다른 증거다.

현재 남은 운영 gate:

- 테스트 노드의 직접 전송 설정 또는 Java 수신부 활성화와 각각의 자격 증명/네트워크 trust 경계 검토
- 테스트 프로젝트에 저장한 원본 창을 backend에서 다시 조회해 필드 비교
- L7/DNS/coverage의 별도 전송 계약과 p95 재구성에 필요한 분포 보존
- Pod/Service UID와 시간 유효성을 고려한 대상 연결
- 변경된 전체 경로의 대상 커널/OpenShift 및 CNI/런타임 지원 행렬
- 자원 제한 하의 장시간 pressure/churn, 재시작/재연결, 손실 보고
- 단일 노드 canary, immutable image, 최소 권한 및 rollback

이 gate 없이 고객 운영 준비 완료라고 판정하지 않는다.
