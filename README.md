# Pod-ing: K8s Lateral Movement Detection Engine

## 개요
Falco(syscall) + Hubble(network flow) 이벤트를 실시간 수집하여,
FSM 기반 상관분석으로 Kubernetes 측면이동 공격을 탐지합니다.

## 파일 구조
```
poding/
├── engine.py          # 상관분석 엔진 (메인)
├── attack_demo.sh     # 공격 시뮬레이션 스크립트
└── README.md          # 이 파일
```

## 사전 조건
- K8s 클러스터 (kubeadm, 3노드)
- Falco DaemonSet (poding-system 네임스페이스, json_output: true)
- Cilium + Hubble (hubble-relay 동작 중)
- Python 3.8+ (k8s-cp 노드에 설치)
- hubble CLI (k8s-cp 노드에 설치)

## 실행 방법

### 1단계: 파일 전송
로컬(Mac)에서 k8s-cp로 파일 전송:
```bash
scp engine.py attack_demo.sh kguard@k8s-cp:~/poding/
```

### 2단계: Hubble 포트포워딩
k8s-cp에서 터미널1:
```bash
kubectl port-forward -n kube-system deploy/hubble-relay 4245:4245 &
```

### 3단계: 상관분석 엔진 실행
k8s-cp에서 터미널1:
```bash
cd ~/poding
python3 engine.py
```

### 4단계: 공격 시뮬레이션
k8s-cp에서 **터미널2** (새 SSH 세션):
```bash
cd ~/poding

# 테스트 Pod 배포
bash attack_demo.sh setup

# 시나리오 선택 실행
bash attack_demo.sh 1    # Credential Theft
bash attack_demo.sh 2    # Lateral Movement
bash attack_demo.sh 3    # Drop & Execute
bash attack_demo.sh 4    # Full Kill Chain

# 또는 전체 자동 실행
bash attack_demo.sh all

# 정리
bash attack_demo.sh cleanup
```

### 5단계: 결과 확인
터미널1의 engine.py 출력에서:
- `[FALCO]` : Falco 이벤트 수신 및 상태 매핑
- `[HUBBLE]` : Hubble flow 수신 및 상태 매핑
- `[ANOMALY_EDGE]` : 이상 전이 탐지 (1순위)
- `[PATTERN_MATCH]` : 공격 패턴 매칭 (2순위)

## Baseline 모드 (정상 트래픽 학습)
```bash
# 정상 트래픽이 흐르는 상태에서 baseline 수집
BASELINE_MODE=true python3 engine.py
# Ctrl+C로 종료하면 baseline.json 저장됨

# 이후 탐지 모드에서 baseline 활용
python3 engine.py
```

## 환경변수
| 변수 | 기본값 | 설명 |
|------|--------|------|
| FALCO_NS | poding-system | Falco 네임스페이스 |
| HUBBLE_SERVER | localhost:4245 | Hubble relay 주소 |
| SEQ_WINDOW | 60 | 시퀀스 윈도우 (초) |
| BASELINE_MODE | false | baseline 수집 모드 |
| BASELINE_FILE | baseline.json | baseline 파일 경로 |

## 공격 패턴 (등록된 시그니처)
| 패턴명 | 시퀀스 | 설명 |
|--------|--------|------|
| lateral_movement_via_api | s→k→E→s | API 경유 측면이동 |
| credential_theft_exfil | s→c→O | 크레덴셜 탈취 후 반출 |
| credential_theft_network | s→c→n | 크레덴셜 탈취 + 네트워크 |
| drop_and_execute | s→p→b | 도구 설치 후 실행 |
| reverse_shell | s→n→O | 리버스 쉘 |
| recon_and_lateral | s→c→k→E | 정찰 후 측면이동 |
| cryptomining | b→O | 채굴 |
| external_intrusion_lateral | X→s→E | 외부 침입 후 내부 이동 |

## 상태 심볼
| 심볼 | 의미 | 소스 |
|------|------|------|
| s | Shell execution | Falco |
| p | Package management | Falco |
| b | Binary drop/execute | Falco |
| c | Credential/sensitive access | Falco |
| k | K8s API usage | Falco |
| n | Network tool usage | Falco |
| E | Pod-to-Pod flow | Hubble |
| O | Outbound (external) | Hubble |
| X | Inbound (external) | Hubble |
| D | DNS anomaly | Hubble |
