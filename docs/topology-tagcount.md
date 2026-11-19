# 첫 화면용 Workload 연결 요약 TagCount

## 범위와 상태

`kube_network_topology_v1alpha1`은 첫 화면의 **관계·프로토콜·관측 결과 유무**를 위한 별도 category다. 기존 L4/HTTP/DNS/coverage category와 5초 상세 수집을 대체하지 않는다. 새로운 producer는 Go 에이전트의 opt-in 경로이며, 운영 TagMeta 등록·클러스터 RBAC 변경·이미지 배포·실제 저장 후 조회는 별도 승인/검증 대상이다.

고정 캡처 데모의 사전 요약 API는 저장된 캡처에서 파생한 조회 모델이다. 데모 동작이 이 category의 운영 수신을 입증하지 않는다.

## 실행 설정

기존 직접 TagCount 전송 설정에 다음 옵션을 **명시적으로** 추가한다.

```text
-source=ebpf -export=tagcount -output-mode=windows -pod-identity=true
-window=5s
-topology-summary
-topology-window=1m
-topology-max-entries=4096
```

클러스터 이름을 따로 붙이려면 `-topology-cluster-id=NAME`을 더한다. 생략하면 라이선스의 프로젝트 코드(pcode)를 쓴다.

같은 설정은 다음 환경변수로도 지정할 수 있다. 명시한 CLI 인자는 **항목별로** 환경변수보다 우선하며, 적용되는 값은 CLI와 같은 opt-in·형식·범위 검증을 받는다. 잘못된 환경변수 원문은 오류 로그에 남기지 않는다.

| 환경변수 | 대응 인자 | 기본값 |
|---|---|---|
| `WHATAP_TOPOLOGY_SUMMARY` | `-topology-summary` | `false` |
| `WHATAP_TOPOLOGY_CLUSTER_ID` | `-topology-cluster-id` | 라이선스의 프로젝트 코드(pcode) |
| `WHATAP_TOPOLOGY_WINDOW` | `-topology-window` | `1m` |
| `WHATAP_TOPOLOGY_MAX_ENTRIES` | `-topology-max-entries` | `4096` |

Operator가 `networkAgent.env`를 지원하는 배포에서는 기존 CR의 환경변수 목록에 추가한다. 관리되는 DaemonSet 인자를 직접 수정하거나 Operator/CRD를 교체할 필요가 없다. 이 환경변수를 읽는 network-agent 이미지가 필요하며, 기존 환경변수·credentials 참조는 보존한다. 요약을 끌 때는 세부 topology 환경변수도 함께 제거한다. opt-in 없이 세부 설정만 남기면 시작 단계에서 거부한다.

- 기본값은 `-topology-summary=false`다. 기존 배포의 API 권한·송신 category를 자동으로 늘리지 않는다.
- `cluster_id`는 화면에 표시하는 클러스터 이름이다. WhaTap Kubernetes 프로젝트 하나는 클러스터 하나를 모니터링하므로, 설정하지 않으면 라이선스의 프로젝트 코드(pcode)를 쓴다. 이름을 붙이려면 모든 노드에 같은 값을 설정한다. 명시한 빈 값(빈 환경변수 포함)은 생략이 아니라 오류다. 같은 기간 한 프로젝트에서 값이 둘 이상 관측되면 조회 화면은 쿠버 정보를 붙이지 않는다(`multiple-cluster-ids`). Node 이름·OID·현재 kube context를 클러스터 이름으로 쓰지 않는다.
- 요약 창은 1ms~60s의 정수 밀리초이며 상세 flow 창의 배수여야 한다. 기본 요약은 1분, 기존 상세는 5초다. 화면 조회 범위와 수집 창은 별개다.
- max entries는 **모든 활성 시간 창의 연결 키 합계**다. 범위는 1~65,536. 초과하면 오류를 전파하고 중단하며, 일부 관계만으로 완전한 맵이 만들어졌다고 보고하지 않는다.
- summary도 기존 bounded 전송 큐·timeout·drain·실패 진단을 사용한다. `written`은 TCP write 완료이며 저장 ACK가 아니다.
- 닫힌 창의 요약 행은 전송 큐에 자리가 없어도 버리지 않는다. 순서대로 보관했다가 다음 flush에서 다시 넣으므로, 한 창은 전부 전송되거나 오류로 중단된다. 실행 중에 대기 중인 행이 max entries를 넘으면 중단한다. 종료할 때는 마지막 창을 대기 중인 행 뒤에 붙이고, `-output-drain-timeout` 동안 큐가 받는 만큼 넣은 뒤 넣지 못한 행 수를 오류로 보고한다. 전송 오류로 먼저 중단됐다면 보내지 못한 요약 행 수를 종료 오류에 함께 적는다. 상세 category의 큐 초과는 기존대로 `dropped`로 계수한다.
- 실행 중 한 번의 flush는 요약 행을 전송 큐 용량의 절반(최소 1행)까지만 넣고 나머지는 다음 flush로 넘긴다. 닫힌 창의 요약 행이 한꺼번에 들어와 같은 큐를 쓰는 상세 레코드의 자리를 차지하지 않게 하기 위해서다. 전송이 느려 큐가 계속 차 있으면, 그동안 도착한 상세 레코드는 기존대로 `dropped`로 계수된다. flush는 25ms마다 한 번이므로, 요약 창 하나 동안 넣을 수 있는 행 수(창 길이 ÷ 25ms × flush당 몫)가 max entries보다 작은 큐 설정은 시작 단계에서 거부한다. 기본값(큐 1,024, max entries 4,096, 1분 창)은 해당하지 않는다.

## Workload 식별

추가 API 읽기 권한은 `apps/v1 replicasets`와 `batch/v1 jobs`의 cluster-wide `list/watch`다. Pod용 기존 informer와 함께 재사용하고 이벤트마다 API를 호출하지 않는다. 이 문서는 권한 필요 조건이지 운영 RBAC 적용 명령이 아니다.

- Pod controller owner UID를 사용한다. ReplicaSet→Deployment, Job→CronJob은 namespace/name뿐 아니라 중간 객체 UID를 검증한다.
- 동일 이름의 재생성 객체·부모 cache 누락·해석 불가 owner는 known Workload로 채우지 않는다.
- HTTP/매칭 DNS는 최초 request/query의 Pod 및 Workload snapshot을 유지한다. 응답 시점의 최신 객체로 unknown을 보충하지 않는다.
- UID가 없는 대상은 명시적인 unresolved address endpoint다. IP가 남으므로 미식별 대상이 많은 환경에서는 요약 cardinality도 커질 수 있다. 누락 Pod를 곧바로 외부 대상으로 분류하지 않는다.
- 별도 Kubernetes 상태 데이터를 조회하지 않은 이 요약만으로 Ready·정책 적용·Service 경유를 주장하지 않는다.

## 저장 행의 의미

**한 cluster, 시간 창, endpoint 쌍, 프로토콜/방향/확인된 목적지 포트에서 관측이 있었는가.**

분류 차원은 `cluster_id`, 양쪽 endpoint의 kind/UID/name/namespace/address, transport, protocol, direction, 확인된 dst_port다. 실제 송신의 optional 여부·schema 값은 `internal/tagcount/pack_topology.go`와 테스트를 기준으로 한다.

- known Workload에는 Pod 주소·Pod UID·container ID·PID·임시 출발 포트·record_id·HTTP path·DNS query_name을 요약 키로 남기지 않는다.
- L4 canonical tuple은 client/server가 아니므로 방향은 미확정, 목적지 포트도 추정하지 않는다. 양쪽 endpoint 순서를 안정적으로 정규화한다.
- HTTP/DNS는 correlator가 확인한 요청 방향을 사용한다. L4와 HTTP, DNS의 관계를 하나의 요청수/지연으로 합치지 않는다.
- OID는 여전히 전송 observer 식별자다. 저장 엔진의 OID 차원이 사라지는 것은 아니며, 조회 단계에서 동일 관계의 여러 observer 결과를 MAX로 병합한다.

| Field | 타입/단위 | 병합 | 의미 |
|---|---|---|---|
| `observed` | integer flag 0/1 | MAX | 통신 관측 존재 |
| `result_observed` | integer flag 0/1 | MAX | 분류 가능한 HTTP 최종 status / 매칭 DNS 응답 결과 존재 |
| `error_observed` | integer flag 0/1 | MAX | HTTP 4xx/5xx 또는 DNS 오류 응답(SERVFAIL·REFUSED 등) 존재. NXDOMAIN은 검색 도메인 확장에서 정상적으로 나오므로 제외 |
| `last_seen_ms` | int64 epoch-ms | MAX | 마지막 실제 관측 시각, flush 시각 아님 |

Timeout, parse 실패, orphan 응답, coverage drop을 정상 결과로 바꾸지 않는다. `error_observed=0`은 서비스 정상이나 수집 완전성 보장이 아니다. 결과 관측 여부 및 별도 수집 품질을 함께 표시한다. RPS·요청 수·연결 수·SRTT·p95는 이 category에서 계산하지 않는다.

기존 DNS 거래 타입에는 matched 여부가 별도 필드로 없다. 따라서 양의 measured latency가 있는 응답만 요약의 결과 관측으로 인정한다. orphan과 구분할 수 없는 0µs 응답은 원시 데이터에 남기되 요약에서는 결과 미확인이다. wildcard/미바인딩 DNS tuple과 포트 0인 L4 진단 창은 그릴 수 있는 관계가 아니므로 요약에서 제외한다. 기존 진단/skip 경로는 유지한다.

## 최초 조회 계약

1. 인증된 프로젝트 + 명시적인 cluster + 선택 기간으로 **요약 category만** 읽는다.
2. Namespace 선택은 `src_namespace ∈ 선택 OR dst_namespace ∈ 선택`. cross-namespace 관계를 AND 필터로 지우지 않는다.
3. 같은 논리 관계를 시간/OID에 걸쳐 MAX 병합하고, 연결당 한 행을 반환한다. 시계열·Pod history·개별 요청은 첫 응답에 넣지 않는다.
4. 노드·엣지 응답 상한을 적용하고 `truncated`/생략 건수·수집/조회 범위·미식별 상태를 반환한다. 잘린 입력으로 정상/정확한 합계를 표시하지 않는다.
5. 선택 시에만 해당 Workload의 incident edge 또는 선택 edge/Pod의 기존 상세 category를 조회한다. 이전 선택은 취소/세대번호로 무효화하고 project/cluster/time/namespace/selection을 캐시 키로 사용한다.
6. Pod Ready 점과 Service 구성 관계가 필요하면 별도 Kube TagCount의 관심 시각 상태로 축약한 응답을 사용한다. 전체 snapshot history를 초기 맵 때문에 전달하지 않는다.

## TagCount rollup 주의

서버의 TagCount 집계는 `(tagHash, oid)`로 묶고 숫자 필드를 `MetricValue`로 누적한다. 이는 presence의 OR를 자동 수행한다는 뜻이 아니다. base에서는 scalar의 MAX, `{m5}`/`{h1}`에서는 **각 MetricValue의 max 성분을 사용한 MAX**가 필요하다. avg/sum/count로 flag나 마지막 시각을 해석하지 않는다.

태그 수를 줄이는 boundary가 producer인 이유다. 기존 `record_id`/Pod-level raw category를 매번 서버 GROUP으로 축약하면 응답은 줄어도 raw scan 비용은 남는다. 새 category도 OID·활성 관계 수·미식별 주소 수에 비례하므로 절감률을 미리 보장하지 않는다.

이 문서의 조회 단계는 의미 계약이며, 배포 서버에서 검증되지 않은 MXQL `GROUP`/MetricValue accessor 문법을 실행 예제로 발명하지 않는다. 운영 도입 gate는 TagMeta tag/field 등록, base/m5/h1 MAX 조회 read-back, source와 persisted row 대조, multi-observer/재시작, query scan/응답 bytes 측정이다.

## 검증

```text
make test
make check
make build
go test -race ./internal/podidentity ./internal/topology ./internal/tagcount ./internal/app ./cmd/agentkubenetwork
```

단위·loopback 검증과 실제 Linux 커널→WhaTap 저장 검증은 구분한다. 로컬 macOS에서 성공한 build/test는 운영 readiness나 Kubernetes 버전 호환 실증을 대신하지 않는다.
