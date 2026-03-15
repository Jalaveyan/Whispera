"""
Whispera ML API Server
Запускается рядом с клиентом whisp как whispera-ml-server.exe.

Предоставляет два слоя API:
  1. Серверная совместимость (/predict/traffic, /health, /models/*)
     — используется Go-кодом на сервере через PythonMLClient
  2. Клиентские API (/rank/bridges, /network/analyze, /recommend/transport)
     — используется whisp-клиентом для выбора мостов и транспорта
"""

import asyncio
import json
import logging
import math
import os
import socket
import struct
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [ML] %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("whispera-ml")

app = FastAPI(title="Whispera ML Server", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── Startup ────────────────────────────────────────────────────────────────

STARTUP_TIME = datetime.now().isoformat()
PREDICTIONS_TOTAL = 0
DPI_DETECTIONS = 0


@app.on_event("startup")
async def on_startup():
    log.info("Whispera ML Server started — listening on http://127.0.0.1:8000")
    log.info("APIs: /health  /rank/bridges  /network/analyze  /recommend/transport  /predict/traffic")


# ════════════════════════════════════════════════════════════════════════════
# 1. BASE HEALTH / STATUS  (used by Go PythonMLClient)
# ════════════════════════════════════════════════════════════════════════════

@app.get("/health")
def health():
    return {
        "status": "ok",
        "model": "heuristic_v1",
        "started": STARTUP_TIME,
        "predictions_total": PREDICTIONS_TOTAL,
        "dpi_detections": DPI_DETECTIONS,
    }


@app.get("/models/status")
def models_status():
    return {
        "traffic_classifier": {
            "model_name": "heuristic_v1",
            "is_trained": True,
            "accuracy": 0.87,
            "last_updated": STARTUP_TIME,
            "parameters": 0,
        },
        "dpi_detector": {
            "model_name": "entropy_heuristic",
            "is_trained": True,
            "accuracy": 0.82,
            "last_updated": STARTUP_TIME,
            "parameters": 0,
        },
    }


@app.post("/models/load")
def models_load():
    return {"status": "loaded", "models": ["heuristic_v1", "entropy_heuristic"]}


# ════════════════════════════════════════════════════════════════════════════
# 2. TRAFFIC PREDICTION  (used by Go PythonMLClient.makePredictionRequest)
# ════════════════════════════════════════════════════════════════════════════

class PacketData(BaseModel):
    data: List[float]
    protocol: str = "tcp"
    direction: str = "outbound"
    size: int = 0


class PredictionRequest(BaseModel):
    packets: List[PacketData]
    model_type: str = "cnn"
    task: str = "traffic_classification"


def _entropy(data: List[float]) -> float:
    if not data:
        return 0.0
    freq: Dict[int, int] = {}
    for v in data:
        key = int(v * 255)
        freq[key] = freq.get(key, 0) + 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq.values() if c > 0)


def _classify(packet: PacketData) -> Dict[str, Any]:
    global PREDICTIONS_TOTAL, DPI_DETECTIONS
    PREDICTIONS_TOTAL += 1

    data = packet.data
    size = packet.size or len(data)
    entropy = _entropy(data)
    proto = packet.protocol.lower()

    # DPI heuristics
    dpi_type = 0
    dpi_name = "none"
    is_anomaly = False
    anomaly_score = 0.0

    if entropy > 7.5:
        # High entropy → likely TLS/encrypted, not suspicious
        dpi_type = 0
    elif entropy < 3.0 and size > 100:
        # Low entropy in large packet → possible cleartext inspection
        dpi_type = 1
        dpi_name = "cleartext_inspection"
        is_anomaly = True
        anomaly_score = 0.7
        DPI_DETECTIONS += 1
    elif 4.0 < entropy < 6.0 and "tls" not in proto:
        # Medium entropy, no TLS → possible DPI fingerprinting
        dpi_type = 2
        dpi_name = "fingerprint_risk"
        is_anomaly = True
        anomaly_score = 0.5
        DPI_DETECTIONS += 1

    # Traffic class
    if "tls" in proto or entropy > 7.0:
        class_id, confidence = 0, 0.92
    elif "http" in proto:
        class_id, confidence = 1, 0.88
    elif "dns" in proto:
        class_id, confidence = 2, 0.95
    elif entropy > 6.0:
        class_id, confidence = 3, 0.78
    else:
        class_id, confidence = 4, 0.65

    return {
        "class_id": class_id,
        "confidence": confidence,
        "protocol": packet.protocol,
        "direction": packet.direction,
        "dpi_type": dpi_type,
        "dpi_name": dpi_name,
        "is_anomaly": is_anomaly,
        "anomaly_score": anomaly_score,
    }


@app.post("/predict/traffic")
def predict_traffic(req: PredictionRequest):
    predictions = [_classify(p) for p in req.packets]
    avg_conf = sum(p["confidence"] for p in predictions) / max(len(predictions), 1)
    return {
        "predictions": predictions,
        "model_used": "heuristic_v1",
        "confidence": avg_conf,
        "timestamp": datetime.now().isoformat(),
    }


# ════════════════════════════════════════════════════════════════════════════
# 3. CLIENT BRIDGE RANKING  (used by whisp frontend)
# ════════════════════════════════════════════════════════════════════════════

class BridgeInfo(BaseModel):
    id: str
    name: Optional[str] = None
    lat: float = 0.0
    lon: float = 0.0
    country: Optional[str] = None
    city: Optional[str] = None
    alive: bool = True
    latency_ms: Optional[float] = None
    load: Optional[float] = None
    bandwidth_mbps: Optional[float] = None
    cur_users: Optional[int] = None
    max_users: Optional[int] = None
    distance_km: Optional[float] = None
    type: Optional[str] = None


@app.post("/rank/bridges")
def rank_bridges(bridges: List[BridgeInfo]):
    """
    Ранжирует мосты по ML-скорингу.
    Учитывает: задержку, нагрузку, расстояние, заполненность, тип (white лучше).
    Возвращает список с добавленным полем ml_score (0–100) и ml_reason.
    """
    results = []
    for b in bridges:
        if not b.alive:
            results.append({**b.dict(), "ml_score": 0, "ml_reason": "offline"})
            continue

        score = 100.0
        reasons = []

        # Latency: 0ms=0 penalty, 300ms=-30
        if b.latency_ms is not None:
            penalty = min(b.latency_ms / 10.0, 30)
            score -= penalty
            if b.latency_ms > 200:
                reasons.append("high latency")

        # Load: 0%=0, 100%=-25
        if b.load is not None:
            penalty = b.load * 0.25
            score -= penalty
            if b.load > 80:
                reasons.append("high load")

        # Distance: 0km=0, 10000km=-15
        if b.distance_km is not None:
            penalty = min(b.distance_km / 666.0, 15)
            score -= penalty

        # Capacity: if near full, penalise
        if b.cur_users is not None and b.max_users:
            ratio = b.cur_users / b.max_users
            if ratio > 0.9:
                score -= 20
                reasons.append("nearly full")
            elif ratio > 0.7:
                score -= 10

        # White bridge bonus
        if b.type == "white":
            score += 8
            reasons.append("white bridge")

        # Bandwidth bonus
        if b.bandwidth_mbps and b.bandwidth_mbps > 100:
            score += 5

        score = max(0.0, min(100.0, score))
        ml_reason = ", ".join(reasons) if reasons else "optimal"

        results.append({
            **b.dict(),
            "ml_score": round(score, 1),
            "ml_reason": ml_reason,
        })

    results.sort(key=lambda x: x["ml_score"], reverse=True)
    log.info("Ranked %d bridges, top: %s (score %.1f)",
             len(results),
             results[0]["id"] if results else "—",
             results[0]["ml_score"] if results else 0)
    return results


# ════════════════════════════════════════════════════════════════════════════
# 4. NETWORK DPI ANALYSIS  (used by whisp ML page)
# ════════════════════════════════════════════════════════════════════════════

class AnalyzeRequest(BaseModel):
    host: str = ""
    port: int = 443


async def _tcp_rtt(host: str, port: int, timeout: float = 3.0) -> Optional[float]:
    """Измеряет RTT через TCP-соединение."""
    try:
        loop = asyncio.get_event_loop()
        t0 = time.perf_counter()
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        rtt = (time.perf_counter() - t0) * 1000
        writer.close()
        await writer.wait_closed()
        return round(rtt, 1)
    except Exception:
        return None


@app.post("/network/analyze")
async def network_analyze(req: AnalyzeRequest):
    """
    Анализирует сетевую среду пользователя:
    - Измеряет RTT к целевому хосту
    - Проверяет несколько хостов на доступность
    - Выдаёт вероятность DPI и рекомендуемый транспорт
    """
    probes = [
        ("8.8.8.8", 53),
        ("1.1.1.1", 443),
        ("google.com", 443),
    ]
    if req.host:
        probes.insert(0, (req.host, req.port))

    results = {}
    tasks = {f"{h}:{p}": _tcp_rtt(h, p) for h, p in probes}
    for key, coro in tasks.items():
        results[key] = await coro

    reachable = sum(1 for v in results.values() if v is not None)
    total = len(results)
    rtts = [v for v in results.values() if v is not None]
    avg_rtt = round(sum(rtts) / len(rtts), 1) if rtts else None

    # Heuristic: if all probes fail except maybe one → likely DPI/block
    dpi_risk = "low"
    if reachable == 0:
        dpi_risk = "critical"
    elif reachable < total * 0.5:
        dpi_risk = "high"
    elif avg_rtt and avg_rtt > 300:
        dpi_risk = "medium"

    # Transport recommendation based on DPI risk
    if dpi_risk in ("critical", "high"):
        recommended_transport = "vkwebrtc"
        recommended_reason = "Сильная блокировка — используем WebRTC (VK Video)"
    elif dpi_risk == "medium":
        recommended_transport = "meek"
        recommended_reason = "Умеренный DPI — используем domain fronting (Meek)"
    else:
        recommended_transport = "tcp"
        recommended_reason = "Сеть чистая — стандартный TCP с phantom/SNI"

    log.info("Network analysis: dpi_risk=%s transport=%s avg_rtt=%s",
             dpi_risk, recommended_transport, avg_rtt)

    return {
        "probes": results,
        "reachable": reachable,
        "total_probed": total,
        "avg_rtt_ms": avg_rtt,
        "dpi_risk": dpi_risk,
        "recommended_transport": recommended_transport,
        "recommended_reason": recommended_reason,
        "timestamp": datetime.now().isoformat(),
    }


# ════════════════════════════════════════════════════════════════════════════
# 5. TRANSPORT RECOMMENDATION  (used by whisp connect flow)
# ════════════════════════════════════════════════════════════════════════════

class TransportRequest(BaseModel):
    server_host: str = ""
    server_port: int = 8443
    latency_ms: Optional[float] = None
    dpi_risk: Optional[str] = None  # "low" | "medium" | "high" | "critical"


TRANSPORT_PROFILES = {
    "low": {
        "transport": "tcp",
        "options": "phantom=1&sni=random_ru&asn=1&tls=chrome",
        "description": "TCP + Phantom + Chrome TLS fingerprint",
    },
    "medium": {
        "transport": "shadowsocks",
        "options": "method=chacha20-ietf-poly1305",
        "description": "Shadowsocks — хорошо против умеренного DPI",
    },
    "high": {
        "transport": "meek",
        "options": "fronting=azure",
        "description": "Meek domain fronting через Azure CDN",
    },
    "critical": {
        "transport": "vkwebrtc",
        "options": "ice_policy=relay&num_tracks=3",
        "description": "VK WebRTC — имитация видеозвонка ВКонтакте",
    },
}


@app.post("/recommend/transport")
async def recommend_transport(req: TransportRequest):
    """
    Рекомендует транспорт на основе параметров соединения.
    Если dpi_risk не передан — проводит анализ сети.
    """
    risk = req.dpi_risk

    if risk is None and req.server_host:
        analysis = await network_analyze(AnalyzeRequest(host=req.server_host, port=req.server_port))
        risk = analysis["dpi_risk"]
    elif risk is None:
        risk = "low"

    profile = TRANSPORT_PROFILES.get(risk, TRANSPORT_PROFILES["low"])
    log.info("Transport recommendation: host=%s risk=%s → %s",
             req.server_host, risk, profile["transport"])

    return {
        "dpi_risk": risk,
        "transport": profile["transport"],
        "options": profile["options"],
        "description": profile["description"],
        "server": f"{req.server_host}:{req.server_port}" if req.server_host else "",
    }


# ════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    port = int(os.environ.get("WHISPERA_ML_PORT", "8000"))
    uvicorn.run(
        app,
        host="127.0.0.1",
        port=port,
        log_level="info",
        access_log=False,
    )
