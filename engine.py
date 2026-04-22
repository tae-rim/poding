#!/usr/bin/env python3
"""
Pod-ing: Kubernetes Lateral Movement Detection Engine (v2)
==========================================================
v2 수정사항:
  - kubectl logs prefix 처리 (Pod이름 prefix 제거)
  - JSON 파싱 강화 (줄 중간에 JSON이 있는 경우)
  - 개별 Falco Pod별 수집 스레드
  - 패턴 매칭 중복 알림 방지
  - 시스템 네임스페이스 Hubble 노이즈 필터링
"""

import json
import subprocess
import threading
import time
import sys
import os
from datetime import datetime, timezone
from collections import defaultdict, deque
from typing import Optional

# ─────────────────────────────────────────────
# 설정
# ─────────────────────────────────────────────
FALCO_NAMESPACE = os.environ.get("FALCO_NS", "poding-system")
HUBBLE_SERVER = os.environ.get("HUBBLE_SERVER", "localhost:4245")
SEQUENCE_WINDOW = int(os.environ.get("SEQ_WINDOW", "120"))
MAX_EVENTS_PER_POD = int(os.environ.get("MAX_EVENTS", "200"))
BASELINE_MODE = os.environ.get("BASELINE_MODE", "false").lower() == "true"
BASELINE_FILE = os.environ.get("BASELINE_FILE", "baseline.json")

IGNORE_NAMESPACES = {
    "kube-system", "poding-system", "monitoring",
    "cilium", "hubble",
}

# ─────────────────────────────────────────────
# 1. Falco Rule → State Symbol 매핑
# ─────────────────────────────────────────────
FALCO_RULE_TO_STATE = {
    "Terminal shell in container": "s",
    "Run shell untrusted": "s",
    "Launch Package Management Process in Container": "p",
    "Update Package Repository": "p",
    "Drop and execute new binary in container": "b",
    "Execution from /dev/shm": "b",
    "Fileless execution via memfd_create": "b",
    "Write below binary dir": "b",
    "Read sensitive file untrusted": "c",
    "Read sensitive file trusted after startup": "c",
    "Create Symlink Over Sensitive Files": "c",
    "Create Hardlink Over Sensitive Files": "c",
    "Search Private Keys or Passwords": "c",
    "Find AWS Credentials": "c",
    "Write below etc": "c",
    "Contact K8S API Server From Container": "k",
    "Kubernetes Client Tool Launched in Container": "k",
    "Launch Suspicious Network Tool in Container": "n",
    "Netcat Remote Code Execution in Container": "n",
    "Launch Ingress Remote File Copy Tools in Container": "n",
    "Launch Remote File Copy Tools in Container": "n",
    "Redirect STDOUT/STDIN to Network Connection in Container": "O",
    "Exfiltrating Artifacts via Kubernetes Control Plane": "c",
    "Detect crypto miners using the Stratum protocol": "b",
    # Pod-ing 커스텀 룰
    "Pod-ing K8s API Access from Container": "k",
    "Pod-ing SA Token Read": "c",
    "Pod-ing Netcat Execution in Container": "n",
    "Pod-ing External Download in Container": "n",
}

# ─────────────────────────────────────────────
# 2. Hubble Flow → State Symbol 매핑
# ─────────────────────────────────────────────
def classify_hubble_flow(flow: dict) -> Optional[str]:
    inner = flow.get("flow", flow)
    src_labels = inner.get("source", {}).get("labels", [])
    dst_labels = inner.get("destination", {}).get("labels", [])
    src_pod = inner.get("source", {}).get("pod_name", "")
    dst_pod = inner.get("destination", {}).get("pod_name", "")
    src_ns = inner.get("source", {}).get("namespace", "")
    dst_ns = inner.get("destination", {}).get("namespace", "")

    if not src_pod and not dst_pod:
        return None

    l7 = inner.get("l7", {})
    dns = l7.get("dns", {})
    if dns and dns.get("rcode", 0) == 3:
        return "D"

    src_is_world = any("reserved:world" in l for l in src_labels)
    dst_is_world = any("reserved:world" in l for l in dst_labels)

    if src_is_world and dst_pod:
        return "X"
    if dst_is_world and src_pod:
        return "O"
    if src_pod and dst_pod:
        if src_ns not in IGNORE_NAMESPACES or dst_ns not in IGNORE_NAMESPACES:
            return "E"

    return None


def get_pod_id_from_hubble(flow: dict) -> Optional[str]:
    inner = flow.get("flow", flow)
    src = inner.get("source", {})
    dst = inner.get("destination", {})
    src_pod, src_ns = src.get("pod_name", ""), src.get("namespace", "")
    dst_pod, dst_ns = dst.get("pod_name", ""), dst.get("namespace", "")

    if src_pod and src_ns and src_ns not in IGNORE_NAMESPACES:
        return f"{src_ns}/{src_pod}"
    if dst_pod and dst_ns and dst_ns not in IGNORE_NAMESPACES:
        return f"{dst_ns}/{dst_pod}"
    if src_pod and src_ns:
        return f"{src_ns}/{src_pod}"
    if dst_pod and dst_ns:
        return f"{dst_ns}/{dst_pod}"
    return None

# ─────────────────────────────────────────────
# 3. 정규화된 이벤트
# ─────────────────────────────────────────────
class NormalizedEvent:
    def __init__(self, timestamp, pod_id, state, source, rule, raw=None):
        self.timestamp = timestamp
        self.pod_id = pod_id
        self.state = state
        self.source = source
        self.rule = rule
        self.raw = raw or {}
        try:
            self.dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        except:
            self.dt = datetime.now(timezone.utc)

    def to_dict(self):
        return {"timestamp": self.timestamp, "pod_id": self.pod_id,
                "state": self.state, "source": self.source, "rule": self.rule}

    def __repr__(self):
        return f"[{self.state}] {self.pod_id} | {self.rule} ({self.source})"

# ─────────────────────────────────────────────
# 4. 공격 패턴 정의
# ─────────────────────────────────────────────
ATTACK_PATTERNS = [
    {"name": "lateral_movement_via_api", "sequence": ["s", "k", "E", "s"],
     "description": "쉘 진입 → K8s API 접근 → Pod간 이동 → 2차 쉘",
     "severity": "CRITICAL", "mitre": "T1609 → Lateral Movement"},
    {"name": "credential_theft_exfil", "sequence": ["s", "c", "O"],
     "description": "쉘 진입 → 민감파일 읽기 → 외부 전송",
     "severity": "HIGH", "mitre": "T1555 → T1048 Exfiltration"},
    {"name": "credential_theft_network", "sequence": ["s", "c", "n"],
     "description": "쉘 진입 → 민감파일 읽기 → 네트워크 도구 사용",
     "severity": "HIGH", "mitre": "T1555 → Lateral Movement prep"},
    {"name": "drop_and_execute", "sequence": ["s", "p", "b"],
     "description": "쉘 진입 → 패키지/도구 설치 → 바이너리 실행",
     "severity": "HIGH", "mitre": "T1059 → T1105 → T1204"},
    {"name": "reverse_shell", "sequence": ["s", "n", "O"],
     "description": "쉘 진입 → netcat/네트워크 도구 → 외부 연결",
     "severity": "CRITICAL", "mitre": "T1059 → T1571"},
    {"name": "recon_and_lateral", "sequence": ["s", "c", "k", "E"],
     "description": "쉘 진입 → 크레덴셜 수집 → API 접근 → 측면이동",
     "severity": "CRITICAL", "mitre": "Full Kill Chain"},
    {"name": "cryptomining", "sequence": ["b", "O"],
     "description": "바이너리 실행 → 외부 통신 (채굴 풀)",
     "severity": "MEDIUM", "mitre": "T1496 Resource Hijacking"},
    {"name": "external_intrusion_lateral", "sequence": ["X", "s", "E"],
     "description": "외부 인입 → 쉘 획득 → 내부 이동",
     "severity": "CRITICAL", "mitre": "Initial Access → Lateral Movement"},
]

# ─────────────────────────────────────────────
# 5. Subsequence 매칭
# ─────────────────────────────────────────────
def subsequence_match(sequence, pattern):
    pi = 0
    for s in sequence:
        if pi < len(pattern) and s == pattern[pi]:
            pi += 1
    return pi == len(pattern)

def find_matching_patterns(sequence):
    return [p for p in ATTACK_PATTERNS if subsequence_match(sequence, p["sequence"])]

# ─────────────────────────────────────────────
# 6. Anomaly Edge Detection
# ─────────────────────────────────────────────
class AnomalyDetector:
    def __init__(self):
        self.baseline = defaultdict(lambda: defaultdict(int))
        self.is_baseline_loaded = False

    def load_baseline(self, filepath):
        try:
            with open(filepath, "r") as f:
                data = json.load(f)
                for group, transitions in data.items():
                    for edge, count in transitions.items():
                        self.baseline[group][edge] = count
            self.is_baseline_loaded = True
            print(f"[BASELINE] 로드 완료: {filepath}")
        except FileNotFoundError:
            print(f"[BASELINE] 파일 없음 — 위험 전이 기반 탐지 모드")

    def save_baseline(self, filepath):
        data = {g: dict(t) for g, t in self.baseline.items()}
        with open(filepath, "w") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        print(f"[BASELINE] 저장 완료: {filepath}")

    def record_transition(self, pod_group, from_state, to_state):
        self.baseline[pod_group][f"{from_state}->{to_state}"] += 1

    def is_anomaly(self, pod_group, from_state, to_state):
        edge = f"{from_state}->{to_state}"
        if not self.is_baseline_loaded:
            dangerous = {
                "c->O": (True, 1.0, "민감파일 접근 직후 외부 전송"),
                "c->n": (True, 0.9, "민감파일 접근 직후 네트워크 도구"),
                "s->k": (True, 0.8, "쉘에서 K8s API 접근"),
                "k->E": (True, 0.7, "K8s API 후 Pod간 이동"),
                "b->O": (True, 0.7, "바이너리 실행 후 외부 통신"),
                "n->O": (True, 0.8, "네트워크 도구 후 외부 연결"),
                "s->b": (True, 0.6, "쉘에서 비인가 바이너리 실행"),
                "p->b": (True, 0.6, "패키지 설치 후 바이너리 실행"),
                "s->c": (True, 0.5, "쉘 진입 후 민감파일 접근"),
            }
            return dangerous.get(edge, (False, 0.0, ""))

        gb = self.baseline.get(pod_group, {})
        if not gb:
            return (True, 0.8, f"'{pod_group}' baseline 없음")
        if edge not in gb:
            return (True, 1.0, f"baseline에 없는 전이: {edge}")
        total = sum(gb.values())
        ratio = gb[edge] / total if total > 0 else 0
        if ratio < 0.01:
            return (True, 0.7, f"희귀 전이: {edge} ({ratio:.2%})")
        return (False, 0.0, "")

# ─────────────────────────────────────────────
# 7. Pod별 이벤트 시퀀스 관리
# ─────────────────────────────────────────────
class PodTracker:
    def __init__(self, anomaly_detector):
        self.pod_events = defaultdict(lambda: deque(maxlen=MAX_EVENTS_PER_POD))
        self.anomaly_detector = anomaly_detector
        self.alert_count = 0
        self.event_count = 0
        self.matched_patterns = defaultdict(set)

    def get_pod_group(self, pod_id):
        parts = pod_id.rsplit("-", 2)
        return parts[0] if len(parts) >= 2 else pod_id

    def add_event(self, event):
        self.event_count += 1
        pod_events = self.pod_events[event.pod_id]

        # Anomaly Edge Detection
        if len(pod_events) > 0:
            prev = pod_events[-1]
            td = (event.dt - prev.dt).total_seconds()
            if 0 <= td <= SEQUENCE_WINDOW:
                pg = self.get_pod_group(event.pod_id)
                is_a, score, reason = self.anomaly_detector.is_anomaly(
                    pg, prev.state, event.state)
                if is_a:
                    self._emit_anomaly(prev, event, score, reason)
                if BASELINE_MODE:
                    self.anomaly_detector.record_transition(pg, prev.state, event.state)

        pod_events.append(event)

        # Pattern Matching
        now = event.dt
        recent = [e.state for e in pod_events
                  if (now - e.dt).total_seconds() <= SEQUENCE_WINDOW]
        for m in find_matching_patterns(recent):
            if m["name"] not in self.matched_patterns[event.pod_id]:
                self.matched_patterns[event.pod_id].add(m["name"])
                self._emit_pattern(event.pod_id, m, recent)

    def _emit_anomaly(self, prev, curr, score, reason):
        self.alert_count += 1
        self._print_alert({
            "type": "ANOMALY_EDGE", "id": self.alert_count,
            "time": curr.timestamp, "pod": curr.pod_id,
            "transition": f"{prev.state} → {curr.state}",
            "score": score, "reason": reason,
        })

    def _emit_pattern(self, pod_id, pattern, sequence):
        self.alert_count += 1
        self._print_alert({
            "type": "PATTERN_MATCH", "id": self.alert_count,
            "time": datetime.now(timezone.utc).isoformat(),
            "pod": pod_id,
            "pattern": pattern["name"],
            "expected": " → ".join(pattern["sequence"]),
            "actual": " → ".join(sequence),
            "severity": pattern["severity"],
            "desc": pattern["description"],
            "mitre": pattern["mitre"],
        })

    def _print_alert(self, a):
        t = a["type"]
        if t == "ANOMALY_EDGE":
            c, icon = "\033[93m", "⚡"
        elif a.get("severity") == "CRITICAL":
            c, icon = "\033[91m", "🚨"
        elif a.get("severity") == "HIGH":
            c, icon = "\033[91m", "⚠️"
        else:
            c, icon = "\033[93m", "📋"
        r = "\033[0m"

        print(f"\n{c}{'='*60}")
        print(f"{icon} [{t}] Alert #{a['id']}")
        print(f"{'='*60}{r}")
        print(f"  시간: {a['time']}")
        print(f"  Pod:  {a['pod']}")
        if t == "ANOMALY_EDGE":
            print(f"  전이: {a['transition']}")
            print(f"  점수: {a['score']:.1f}")
            print(f"  사유: {a['reason']}")
        else:
            print(f"  패턴: {a['pattern']}")
            print(f"  시퀀스: {a['expected']}")
            print(f"  실제:   {a['actual']}")
            print(f"  심각도: {a['severity']}")
            print(f"  설명: {a['desc']}")
            print(f"  MITRE: {a['mitre']}")
        print()
        sys.stdout.flush()

    def print_status(self):
        user_pods = {k: v for k, v in self.pod_events.items()
                     if k.split("/")[0] not in IGNORE_NAMESPACES}
        print(f"\n{'='*60}")
        print(f"  Pod-ing 상태 요약")
        print(f"{'='*60}")
        print(f"  총 이벤트: {self.event_count} | 총 알림: {self.alert_count}")
        print(f"  추적 Pod (사용자): {len(user_pods)}")
        for pid, evts in user_pods.items():
            states = [e.state for e in evts]
            print(f"    {pid}: {' → '.join(states[-15:])}")
            mp = self.matched_patterns.get(pid, set())
            if mp:
                print(f"      ⚠ 매칭: {', '.join(mp)}")
        print()
        sys.stdout.flush()

# ─────────────────────────────────────────────
# 8. JSON 추출 헬퍼
# ─────────────────────────────────────────────
def extract_json(line):
    idx = line.find("{")
    if idx == -1:
        return None
    s = line[idx:]
    depth = 0
    for i, ch in enumerate(s):
        if ch == "{": depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                try:
                    return json.loads(s[:i+1])
                except json.JSONDecodeError:
                    return None
    return None

# ─────────────────────────────────────────────
# 9. Falco 수집기 (개별 Pod별)
# ─────────────────────────────────────────────
def collect_falco_pod(pod_name, tracker, stop_event):
    cmd = ["kubectl", "logs", "-n", FALCO_NAMESPACE, pod_name,
           "-c", "falco", "-f", "--since=1s"]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True, bufsize=1)
        for line in proc.stdout:
            if stop_event.is_set():
                break
            line = line.strip()
            if not line:
                continue
            data = extract_json(line)
            if not data:
                continue
            rule = data.get("rule", "")
            state = FALCO_RULE_TO_STATE.get(rule)
            if not state:
                continue
            fields = data.get("output_fields", {})
            pn = fields.get("k8s.pod.name") or fields.get("k8smeta.pod.name") or ""
            ns = fields.get("k8s.ns.name") or fields.get("k8smeta.ns.name") or "unknown"
            if not pn:
                continue
            pid = f"{ns}/{pn}"
            ts = data.get("time", datetime.now(timezone.utc).isoformat())
            evt = NormalizedEvent(ts, pid, state, "falco", rule, data)
            print(f"  [FALCO] {evt}")
            sys.stdout.flush()
            tracker.add_event(evt)
    except Exception as e:
        print(f"  [FALCO] {pod_name} 에러: {e}")
    finally:
        try: proc.terminate()
        except: pass

def collect_falco_events(tracker, stop_event):
    print("[FALCO] Falco Pod 검색 중...")
    time.sleep(2)
    try:
        r = subprocess.run(
            ["kubectl", "get", "pods", "-n", FALCO_NAMESPACE,
             "-l", "app.kubernetes.io/name=falco",
             "--field-selector=status.phase=Running",
             "-o", "jsonpath={.items[*].metadata.name}"],
            capture_output=True, text=True)
        pods = r.stdout.strip().split()
        print(f"[FALCO] Running Falco Pods: {pods}")
        threads = []
        for p in pods:
            t = threading.Thread(target=collect_falco_pod,
                                 args=(p, tracker, stop_event), daemon=True)
            t.start()
            threads.append(t)
            print(f"[FALCO] {p} 수집 시작")
        for t in threads:
            t.join()
    except Exception as e:
        print(f"[FALCO] 에러: {e}")

# ─────────────────────────────────────────────
# 10. Hubble 수집기
# ─────────────────────────────────────────────
def collect_hubble_events(tracker, stop_event):
    print("[HUBBLE] 이벤트 수집 시작...")
    time.sleep(3)
    cmd = ["hubble", "observe", "--server", HUBBLE_SERVER,
           "-f", "-o", "json"]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True, bufsize=1)
        for line in proc.stdout:
            if stop_event.is_set():
                break
            line = line.strip()
            if not line:
                continue
            data = extract_json(line)
            if not data:
                continue
            state = classify_hubble_flow(data)
            if not state:
                continue
            pid = get_pod_id_from_hubble(data)
            if not pid:
                continue
            inner = data.get("flow", data)
            ts = inner.get("time", datetime.now(timezone.utc).isoformat())
            evt = NormalizedEvent(ts, pid, state, "hubble", f"hubble_{state}", data)
            ns = pid.split("/")[0] if "/" in pid else ""
            if ns not in IGNORE_NAMESPACES:
                print(f"  [HUBBLE] {evt}")
                sys.stdout.flush()
            tracker.add_event(evt)
    except Exception as e:
        print(f"[HUBBLE] 에러: {e}")
    finally:
        try: proc.terminate()
        except: pass

# ─────────────────────────────────────────────
# 11. 메인
# ─────────────────────────────────────────────
def main():
    print(r"""
    ╔═══════════════════════════════════════════╗
    ║  Pod-ing v2                               ║
    ║  K8s Lateral Movement Detection Engine    ║
    ║  Falco + Hubble → FSM Correlation         ║
    ╚═══════════════════════════════════════════╝
    """)
    print(f"  Falco NS:      {FALCO_NAMESPACE}")
    print(f"  Hubble:        {HUBBLE_SERVER}")
    print(f"  윈도우:        {SEQUENCE_WINDOW}초")
    print(f"  Baseline:      {BASELINE_MODE}")
    print(f"  패턴 수:       {len(ATTACK_PATTERNS)}")
    print()

    ad = AnomalyDetector()
    if not BASELINE_MODE:
        ad.load_baseline(BASELINE_FILE)

    tracker = PodTracker(ad)
    stop = threading.Event()

    threading.Thread(target=collect_falco_events, args=(tracker, stop),
                     daemon=True).start()
    threading.Thread(target=collect_hubble_events, args=(tracker, stop),
                     daemon=True).start()

    print("[ENGINE] 실시간 모니터링 시작. Ctrl+C로 종료.\n")

    try:
        while True:
            time.sleep(30)
            tracker.print_status()
    except KeyboardInterrupt:
        print("\n[ENGINE] 종료 중...")
        stop.set()
        if BASELINE_MODE:
            ad.save_baseline(BASELINE_FILE)
        tracker.print_status()
        print("[ENGINE] 종료.")

if __name__ == "__main__":
    main()
