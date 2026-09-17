# Go 수집기의 독립 TagCount 전송

## 실행 경로

`agentkubenetwork` 하나가 수집·집계·전송을 처리한다. Java 노드 에이전트, 로컬 수신 포트, `network-edge-submit`, JSONL 파이프는 필요하지 않다. **기본값은 여전히 전송하지 않는 `-export=none`**이며, 자격 증명이 환경에 있어도 자동으로 활성화되지 않는다.

```text
eBPF → Observation → 완료된 flow.Window
                      ├─ 선택: -stdout=jsonl → JSONL 출력 큐 → stdout
                      └─ -export=tagcount
                           → Go TagCountPack → 제한된 전송 큐
                           → WhaTap TCP 세션 → 수집 서버
```

L7/DNS/coverage도 기존 타입 그대로 별도 TagCount category로 전송하며, `-stdout=jsonl`일 때 진단 JSONL도 출력한다. [L7 TagCount](l7-tagcount.md)에 필드·지연 경계·기존 Kubernetes 데이터 연결 계약을 정리했다. 직접 전송은 `-source=ebpf`와 `-output-mode=windows` 또는 `both`에서만 지원한다. `stdin`의 EOF 기반 배치 동작과 L4 전용 Java 브리지는 변경하지 않는다. 직접 전송과 기존 Java 브리지 전송을 같은 창에 동시에 사용하면 중복 전송될 수 있다.

## 설정

승인된 테스트 프로젝트의 키와 수집 서버를 별도의 접근 제한 파일에 둔다. 아래 값은 **자리 표시자**이며 실제 키를 저장소·명령행·공유 로그에 넣지 않는다.

```properties
accesskey=YOUR_TEST_PROJECT_ACCESS_KEY
whatap.server.host=collector-a.example/collector-b.example
whatap.server.port=6600
```

`-whatap-config`로 지정한 파일만 읽는다. 경로를 생략하면 환경 설정만 사용하며, 다른 저장소나 Java 설정에서 키를 자동으로 가져오지 않는다. 파일은 일반 파일이고 최대 64 KiB여야 한다. 예를 들어 `/etc/whatap-network/whatap.conf`를 수집기 실행 계정만 읽을 수 있도록 준비한다.

| 환경 변수 | 파일 키 | 의미 |
|---|---|---|
| `WHATAP_ACCESSKEY` | `accesskey` | 프로젝트와 세션 인증에 사용할 키 |
| `WHATAP_LICENSE` | `license` | 키의 호환 별칭 |
| `WHATAP_SERVER_HOST` | `whatap.server.host` | `/`로 구분한 수집 서버 호스트; IPv6 가능 |
| `WHATAP_SERVER_PORT` | `whatap.server.port` | TCP 포트; 기본 6600 |
| `WHATAP_OBJECT_NAME` | `whatap.name` | 이 수집기의 독립 객체 이름 |

환경 변수가 파일보다 우선한다. `net_udp_port`는 예전 설정 호환용 포트 대체 키이며 **UDP 전송을 의미하지 않는다**. 객체 이름을 지정하지 않으면 `kube-network-<node-name>`을 사용하고, 이 이름의 WhaTap 해시를 OID로 사용한다. 동일 프로젝트에서 노드별로 고유하고 재시작 후에도 안정적인 이름을 사용한다. 다른 에이전트의 이름을 재사용하면 OID가 충돌할 수 있다.

프로젝트 코드는 키에서 가져오고 OID는 이 Go 수집기가 소유한다. Java의 OID/ONODE를 추측하거나 자동으로 연결하지 않는다. 현재 ONODE는 0이다. 잘못된 키·주소·전송 제한은 BPF 부착 전에 거절하며 오류에 키 원문을 출력하지 않는다.

## 실행

지원되는 Linux 테스트 노드에서만 실행한다. 실제 프로젝트에 데이터를 보내므로 키·대상 서버·관측 범위를 먼저 승인한다.

```bash
make build
sudo ./bin/agentkubenetwork \
  -source=ebpf -node-name=TEST_NODE \
  -output-mode=windows -window=5s -allowed-lateness=1s \
  -export=tagcount -whatap-config=/etc/whatap-network/whatap.conf \
  -tagcount-queue=1024 -tagcount-timeout=5s \
  -tagcount-drain-timeout=5s -duration=30s
```

- `-duration=0`은 SIGINT/SIGTERM까지 수집한다. 정상 종료 시 창을 먼저 마무리한 뒤 전송 큐를 drain한다.
- `-window`는 직접 전송 시 1ms~60s 범위의 정수 밀리초여야 한다.
- 창이 완료되기 전에 종료하면 `partial`로 남으며 보내지 않는다. 너무 짧은 수집 시간에 `written=0`인 것은 연결 실패의 증거가 아니다.
- 기본 `-stdout=auto`는 TagCount 전송 시 중복 JSONL을 끈다. `-stdout=jsonl`로 복원한다. `-log-level=info -log-interval=1m`은 stderr 주기 요약이며, `0` 또는 warn/error에서는 주기 요약만 끈다. 종료 요약과 fatal 오류는 항상 유지한다. [로그 설정](logging.md)을 참고한다. `both`의 raw TCP 진단에는 command line이 포함될 수 있으나 TagCount에는 보내지 않는다.
- `-output-queue`와 `-output-drain-timeout`은 JSONL용이다. 전송 큐/제한 시간과 별개이며 종료 대기 시간이 합산될 수 있다.

## 팩 계약

`internal/tagcount/pack.go`는 기존 `bridge.RequestForWindow`의 **네트워크 동작이 없는 검증·필드 변환 함수**를 재사용한다. Java 브리지 클라이언트는 호출하지 않는다. `golib`의 실제 `TagCountPack`과 직렬화 코덱을 사용한다.

- category: `kube_network_edge_v1alpha1`; 팩 시각: 원래 창 시작 시각.
- tags: schema, observer node/role, TCP, 양쪽 주소, 선택적 observer container 및 NAT 보강 주소/방식.
- fields: 양쪽 포트, 창 시작/종료, `srtt_count/sum_us/min_us/max_us`, 선택적 NAT 보강 포트.
- `partial`, SRTT count 0, 양쪽 중 포트가 0인 불완전 TCP tuple 창은 제외한다. 누락된 포트를 추정하거나 정상 값으로 채우지 않으며, 나머지 창 수집은 계속한다. PID, comm, command line, 키, 로컬 request ID는 팩에 넣지 않는다.
- 포트는 tag가 아닌 field다. count는 연결/요청 수가 아니라 실제 SRTT 샘플 수다. p95, HTTP 지연, bytes/loss 등의 미측정 값을 만들어 넣지 않는다.

이 category의 backend 보존·조회 계약, Pod/Service UID 연결, 분포 전송은 별도 검증 대상이다.

## 전송과 실패의 의미

`internal/whatap`은 `npmagent/gointernal`의 라이선스 형식과 AES-128 key-reset/TCP 프레이밍에 필요한 부분을 작은 수명주기 관리형 클라이언트로 이식한다. 원본의 전역 singleton, 끝나지 않는 재접속 루프, 키 로깅, 원격 명령 실행은 가져오지 않는다. 빌드/실행에 `npmagent` 체크아웃이나 로컬 `replace`는 필요하지 않다.

- 연결은 재사용한다. 패킷은 원본 Sender도 지원하는 `NET_SECURE_CYPHER`로 전송하고, 키 협상 실패 시 평문으로 대체하지 않는다.
- 키 협상 응답 헤더의 전송 키는 0 또는 복호화한 본문에서 발급한 키와 같은 값만 허용한다. 프로젝트·객체·응답 종류나 헤더/본문 키가 불일치하면 거절한다.
- 이 방식은 기존 WhaTap의 **AES-ECB 호환 프로토콜이지 TLS나 인증 암호화(AEAD)가 아니다**. `secure`라는 원본 패키지 이름만으로 현대적인 전송 보안이 보장된다고 해석하지 않는다. 승인된 네트워크 경계에서만 사용한다.
- 아직 데이터 팩을 쓰지 않은 연결·협상 단계에서만 설정된 다른 서버를 시도할 수 있다. 전체 연결·협상·쓰기에는 요청 제한 시간이 적용된다.
- 전송 오류는 수집 경로에 전파되고 nonzero 종료한다. 쓰기 후 결과가 불명확한 팩을 자동 재전송하지 않는다. 지속 재시도, 디스크 버퍼, exactly-once는 제공하지 않는다.
- 큐는 기본 1,024개, 최대 16,384개다. 꽉 차면 수집 루프를 대기시키지 않고 창을 누락 계수한다. JSONL의 `network.tagcount.drop/v1alpha1`과 최종 요약으로 보고하며, 큐 손실이 있으면 종료 결과도 nonzero다.
- 종료 제한 시간 초과 시 네트워크 작업을 취소하고 연결을 닫는다. 남아 있는 창을 성공으로 세지 않는다.
- 수집 취소로 직접 닫은 ring reader의 `os.ErrClosed`는 정상 종료로 처리한다. 중단 요청 전 발생한 닫힘 오류와 다른 읽기 오류는 숨기지 않는다.
- `-stdout=jsonl`이면 export가 창을 거절해도 해당 창과 이미 drain한 같은 배치의 나머지 JSONL 기록을 먼저 큐에 남긴다. 첫 거절 뒤 같은 배치를 추가 전송하지 않으며, JSONL 큐·drain 한계는 그대로 적용된다.

종료 요약의 `stage`는 `tcp_write`다.

| 항목 | 의미 |
|---|---|
| `queued` | 전송 큐에 들어간 레코드(L4/HTTP/DNS/coverage 합계) |
| `written` | TCP 쓰기가 오류 없이 끝난 레코드; **서버 저장/ACK가 아님** |
| `failed` | 전송 시도에서 오류가 난 레코드; 수신 여부가 불명확할 수 있음 |
| `pending` | 큐에 들어갔지만 쓰기 완료/실패로 아직 분류되지 않은 레코드 |
| `dropped` | 큐 초과로 들어가지 못한 레코드 |
| `skipped_partial`, `skipped_unmeasured`, `skipped_incomplete_tuple` | 계약상 전송 대상이 아닌 창; 포트가 없는 관측도 별도로 계수 |

## 검증 경계

로컬 테스트는 합성 키와 loopback 수집 서버로 팩 직렬화, 키 협상, TCP 프레임, 연결 재사용, 잘못된 입력/응답, 취소, 큐 초과, 종료와 CLI 연결을 검사한다. 기존 수집기 회귀 테스트도 유지한다.

```bash
go test -race -count=1 ./internal/whatap ./internal/tagcount ./internal/app ./cmd/agentkubenetwork
```

이 테스트는 실제 WhaTap 서버나 실제 Linux 커널 수집부터 저장까지의 종단 검증이 아니다. 운영 전에 승인된 테스트 프로젝트에서 원래 창 시간·observer node·tuple로 조회하여 입력 건수와 count/sum/min/max를 비교해야 한다. 실제 노드 배포, 지속 부하·손실, 재시작 정책과 기존 에이전트와의 객체 연결도 별도 gate다.