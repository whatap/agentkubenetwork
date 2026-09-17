# Go → Java 로컬 네트워크 수집 연동

이 문서는 기존 **선택적 브리지 경로**를 설명한다. Java 없이 수집기 실행파일 하나에서 서버로 보내려면 [독립 Go TagCount 전송](direct-tagcount.md)을 사용한다. 두 경로로 같은 창을 중복 전송하지 않는다.

## 범위와 상태

실제 Go 클라이언트와 Java 수신부 사이의 TCP 왕복, `TagCountPack` 생성·직렬화, 로컬 큐 수락 여부까지 구현한다. **서버 저장·조회 성공을 의미하지 않는다.** 이번 변경에서는 기존 에이전트 배포, 기존 수신 포트 변경, 백엔드 데이터 전송을 하지 않았다.

```text
agentkubenetwork --source ebpf --output-mode windows
  → network.flow/v1alpha1 JSONL
  → network-edge-submit
  → 별도 loopback TCP 수신부
  → bounded preflight → 공식 Whatap MapValue decoder
  → NetworkEdgeRecordBuilder
  → DataPackSender.trySendNetworkEdge
  → TcpRequestMgr.tryAdd (클러스터 큐 / 기존 offline buffer)
```

기존 `node_listen_port`의 legacy micro handler를 우회해 **별도 포트**를 사용한다. 프레이밍과 MapValue 코덱은 공식 구현을 재사용하며, 백엔드 인증·암호화 프로토콜을 Go에서 구현하지 않는다.

## 입력·측정 계약

- 실제 생산자 스키마는 `network.flow/v1alpha1`이다. 임의의 다른 이름으로 바꾸지 않는다.
- 완료된 L4/TCP 창의 **측정된 SRTT**만 전송한다. `partial` 및 sample count 0 창은 제외하고 수량을 보고한다.
- 이것은 서비스 edge가 아니라 원본 tuple·observer별 flow 창이다. source ephemeral port는 tag가 아니라 field이다.
- 요청 스키마는 `network.edge.window/v1alpha1`; category는 Java의 `kube_network_edge_v1alpha1` 상수다. **이 category의 운영 저장·보존·조회 계약은 아직 승인/검증된 것이 아니다.**
- 원래 window 시간, 주소·포트, SRTT count/sum/min/max, 양쪽 resolution snapshot을 보존한다.
- 현재 팩에는 p95나 병합 가능한 히스토그램이 없다. count/sum/min/max만으로 화면의 p95를 재구성하거나 창별 p95를 평균내면 안 된다. 분포 전송 계약을 추가하기 전에는 이 팩으로 기존 p95 차트를 대체하지 않는다.
- 컨테이너는 observer identity다. 방향을 증명할 수 없으면 `observer_role=unknown`이며 canonical source로 추측하지 않는다.
- PID, command line, license, request ID를 backend tags/fields에 넣지 않는다. request ID는 로컬 상관 확인용이다.
- 프로젝트·OID·ONODE·node binding은 Java의 신뢰 설정에서 결정한다. producer가 category나 프로젝트를 선택할 수 없다.

## 수신 안전장치

- 신규 listener는 loopback에만 bind한다. **loopback은 같은 호스트/hostNetwork 프로세스에 대한 인증 수단이 아니다.** 운영 적용 전에 별도 trust 경계 검토가 필요하다.
- 한 연결에 한 프레임: `BE uint16 0xCAFE | BE int32 body length | MapValue`.
- request body 최대 64 KiB, ACK 최대 4 KiB. 전체 입력 프레임에 deadline을 적용해 조금씩 보내는 연결도 제한한다.
- 길이 제한 이후에도 내부 선언 길이·중복 키·UTF-8·남은 바이트·타입·필드 allowlist를 검사한 다음 공식 decoder를 호출한다.
- 성공 ACK의 `stage=node_queue`는 실제 노드 측 queue/offline buffer가 수락했다는 뜻이다. 이후 버퍼 만료·퇴거나 서버 손실은 별개다.
- 거절은 성공으로 세지 않는다. ACK가 불명확하면 자동 재전송하지 않는다. 수동 재전송 중복 제거와 exactly-once는 제공하지 않는다.
- CLI는 처리 실패 시에도 accepted/failed/skipped 수량을 출력하고 nonzero로 종료한다.

## 기본 설정 — 이번 작업에서 활성화하지 않음

```properties
network_edge_ingest_enabled=false
network_edge_ingest_port=0
network_edge_ingest_node=
```

운영 부팅 경로에서 활성화하려면 별도의 nonzero port와 정확한 node 이름이 필요하다. 노드 설정과 수집기 `-node-name`이 일치해야 한다. 검증 스크립트의 `--node`는 보관된 입력을 검증하는 별도 인자다. 포트·node binding 변경은 재시작이 필요하며, 런타임 비활성화는 새로운 수신/queue 진입을 차단한다. 이미 수락된 데이터는 취소하지 않는다.

AgentBoot는 시작 실패로 기존 수집을 중단하지 않고 `NETWORK_EDGE_DISABLED`를 기록한다. 시작 시 `NETWORK_EDGE_LISTEN`, 종료 실패 시 `NETWORK_EDGE_CLOSE_FAILED`를 기록한다. 오류에 payload나 자격 증명을 출력하지 않는다.

## 로컬 검증 재현 — 실제 에이전트 부팅 없음

기본 빌드는 수집기와 TagCount 전송기 두 실행 파일을 모두 만든다. `BIN_DIR`을 지정하면 기존 실행파일을 덮지 않고 별도 경로에 빌드한다.

```sh
make build
```

통합 검증 스크립트는 Go 전체 race 검사, CLI 빌드, 선택된 Java unit/interop 검사, 실제 TCP 왕복, 모든 필드와 중복 multiplicity 비교를 실행한다.

```sh
python3 scripts/verify_local_bridge.py \
  --java-repo /path/to/agentkubejava \
  --maven /path/to/mvn \
  --go /path/to/go \
  --input internal/bridge/testdata/producer-window.jsonl \
  --node hermes-loopback-validation \
  --output-dir /tmp/network-edge-local-proof
```

- `JAVA_HOME`은 Java 8을 지정한다. Maven 의존성은 기존 cache를 사용하는 offline 검사다.
- `--input`은 JSONL이다. 여러 줄로 pretty-print한 JSON 파일이 아니다.
- `--output-dir`은 새 디렉터리여야 한다. summary.json, 예상/실제 TSV, 테스트 로그, 테스트에 사용한 Go 바이너리가 남는다.
- 기본 예제는 실제 Linux loopback 수집에서 보존한 fixture 한 건이다. 더 큰 캡처 JSONL을 지정해도 된다. 선택된 모든 창은 명시한 `--node`와 일치해야 한다.
- 검증 스크립트는 `make build BIN_DIR=...`로 두 실행파일을 새 출력 경로에 빌드하고 각각의 SHA256을 보관한다.
- 통합 테스트의 sink는 **로컬 캡처 fixture**이며 real backend가 아니다. 별도 queue 테스트는 worker를 시작하지 않는 실제 큐 객체를 사용한다.
- receiver 생성만으로 TcpSession이 시작되는 legacy 동작이 있어 테스트 seam은 worker **생성 자체**를 하지 않는다.

## 연속 L4 전송 — 승인된 테스트 노드에서만

다음 명령은 새 커널 수집과 실제 노드 큐 전송을 시작한다. 로컬 검증 스크립트와 달리, **테스트 프로젝트·노드·전용 listener 설정을 먼저 승인한 경우에만** 실행한다. listener는 기본 비활성화이며 여기서 임의로 활성화하지 않는다. 기존 micro 포트나 서버의 6600 포트를 그대로 넣지 않는다.

```bash
: "${NODE_NAME:?set the exact approved node name}"
: "${NETWORK_EDGE_INGEST_PORT:?set the dedicated listener port}"
set -o pipefail
sudo ./bin/agentkubenetwork \
  -source=ebpf -node-name="$NODE_NAME" \
  -output-mode=windows -window=5s -allowed-lateness=1s \
  -output-queue=4096 -output-drain-timeout=5s -duration=30s \
  | ./bin/network-edge-submit \
      -address="127.0.0.1:${NETWORK_EDGE_INGEST_PORT}" -timeout=1s
```

- 완료·측정된 L4 창만 전송한다. partial·미측정 창은 skipped, L7/DNS/coverage 등 다른 타입은 ignored로 종료 요약에 집계한다. ignored가 있다는 사실을 전체 화면 지표 전송 성공으로 해석하지 않는다.
- ACK 거절·전송 불명확 시 전송기는 nonzero로 종료한다. `pipefail`을 유지해 생산자 실패도 숨기지 않는다. 자동 재전송·exactly-once는 제공하지 않는다.
- 노드 ACK의 `accepted`는 `node_queue` 수락이다. 서버 저장 확인은 별도로 **같은 테스트 프로젝트와 category, 원래 window 시간, observer_node, tuple**로 조회해서 count/sum/min/max와 입력 건수를 비교해야 한다.
- Pod 상태·HPA·NetworkPolicy Changes는 Kubernetes 에이전트의 권위 있는 관측과 연결한다. 이 Go 전송기가 화면의 상태/색을 수집하거나 Kubernetes watch를 중복 구현하지 않는다.
- 라이선스·프로젝트·OID·ONODE는 기존 Java 노드 에이전트 설정이 담당한다. Go 명령행·JSONL·전송 태그에 추가하지 않는다.

## 아직 남은 운영 검증

실제 프로젝트 저장·조회, backend category/retention 승인, 단일 노드 배포·복구, co-resident 프로세스 신뢰 경계, 지연/오버헤드/손실률의 지속 부하 기준, Pod/Service 시점 join, kernel/CNI/TLS/I/O 방식 지원 행렬은 별도 검증이다. 이 문서의 로컬 통과를 고객 운영 준비 완료로 해석하지 않는다.
