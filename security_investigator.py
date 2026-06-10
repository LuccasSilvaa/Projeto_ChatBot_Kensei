#!/usr/bin/env python3
"""Security investigation agent for IP/domain/URL reputation checks."""

from __future__ import annotations

import argparse
import base64
import ipaddress
import datetime
import json
import os
import sys
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse, quote

import requests


VT_BASE_URL = "https://www.virustotal.com/api/v3"
URLSCAN_BASE_URL = "https://urlscan.io/api/v1"
DEFAULT_TIMEOUT = 20


class InvestigationError(Exception):
    """Raised when the investigation cannot proceed."""


@dataclass
class VirusTotalEvidence:
    available: bool = False
    source: str = "VirusTotal"
    error: str | None = None
    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    reputation: int | None = None
    link: str | None = None
    creation_date: str | None = None
    registrar: str | None = None


@dataclass
class URLScanEvidence:
    available: bool = False
    source: str = "URLScan"
    error: str | None = None
    total_results: int = 0
    malicious_hits: int = 0
    suspicious_hits: int = 0
    highest_score: int | None = None
    sample_result: str | None = None
    server_location: str | None = None
    resolved_ip: str | None = None


@dataclass
class InvestigationReport:
    indicator: str
    indicator_type: str
    classification: str
    explanation: str
    virustotal: VirusTotalEvidence = field(default_factory=VirusTotalEvidence)
    urlscan: URLScanEvidence = field(default_factory=URLScanEvidence)

    def to_dict(self) -> dict[str, Any]:
        return {
            "indicator": self.indicator,
            "indicator_type": self.indicator_type,
            "classification": self.classification,
            "explanation": self.explanation,
            "evidence": {
                "virustotal": self.virustotal.__dict__,
                "urlscan": self.urlscan.__dict__,
            },
        }


def detect_indicator_type(indicator: str) -> str:
    candidate = indicator.strip()
    if not candidate:
        raise InvestigationError("Indicador vazio.")

    parsed = urlparse(candidate)
    if parsed.scheme and parsed.netloc:
        return "url"

    try:
        ipaddress.ip_address(candidate)
        return "ip"
    except ValueError:
        pass

    if "." in candidate and " " not in candidate and "/" not in candidate:
        return "domain"

    raise InvestigationError(
        "Não foi possível identificar o tipo do indicador. Use IP, domínio ou URL válida."
    )


def vt_url_id(raw_url: str) -> str:
    encoded = base64.urlsafe_b64encode(raw_url.encode("utf-8")).decode("utf-8")
    return encoded.rstrip("=")


def fetch_virustotal(indicator: str, indicator_type: str, api_key: str) -> VirusTotalEvidence:
    ev = VirusTotalEvidence()
    headers = {
        "accept": "application/json",
        "x-apikey": api_key,
    }

    gui_link = None
    if indicator_type == "ip":
        endpoint = f"{VT_BASE_URL}/ip_addresses/{indicator}"
        gui_link = f"https://www.virustotal.com/gui/ip-address/{indicator}"
    elif indicator_type == "domain":
        endpoint = f"{VT_BASE_URL}/domains/{indicator}"
        gui_link = f"https://www.virustotal.com/gui/domain/{indicator}"
    elif indicator_type == "url":
        url_id = vt_url_id(indicator)
        endpoint = f"{VT_BASE_URL}/urls/{url_id}"
        gui_link = f"https://www.virustotal.com/gui/url/{url_id}"
    else:
        ev.error = f"Tipo de indicador não suportado no VirusTotal: {indicator_type}"
        return ev
        
    # Salva o link da interface gráfica logo no início, mesmo que a API falhe depois
    ev.link = gui_link

    try:
        response = requests.get(endpoint, headers=headers, timeout=DEFAULT_TIMEOUT)
    except requests.RequestException as exc:
        ev.error = f"Falha de conexão com VirusTotal: {exc}"
        return ev

    if response.status_code == 404:
        ev.error = "Sem registro deste indicador no VirusTotal."
        return ev

    if response.status_code == 429:
        ev.error = "Rate limit do VirusTotal excedido (free tier)."
        return ev

    if response.status_code >= 400:
        ev.error = f"Erro VirusTotal HTTP {response.status_code}: {response.text[:180]}"
        return ev

    try:
        payload = response.json()
    except ValueError:
        ev.error = "Resposta inválida do VirusTotal (JSON malformado)."
        return ev

    attributes = payload.get("data", {}).get("attributes", {})
    stats = attributes.get("last_analysis_stats", {})
    ev.malicious = int(stats.get("malicious", 0) or 0)
    ev.suspicious = int(stats.get("suspicious", 0) or 0)
    ev.harmless = int(stats.get("harmless", 0) or 0)
    ev.undetected = int(stats.get("undetected", 0) or 0)
    reputation = attributes.get("reputation")
    ev.reputation = int(reputation) if isinstance(reputation, int) else None
    
    creation_ts = attributes.get("creation_date")
    if isinstance(creation_ts, int) and creation_ts > 0:
        # Converte timestamp Unix (ex: 1690000000) para data legível (ex: 2023-07-22)
        ev.creation_date = datetime.datetime.fromtimestamp(creation_ts, tz=datetime.timezone.utc).strftime('%d/%m/%Y')
    ev.registrar = attributes.get("registrar")
    
    ev.available = True
    return ev


def _extract_score(result: dict[str, Any]) -> int | None:
    verdicts = result.get("verdicts", {})
    score_candidates = [
        verdicts.get("score"),
        verdicts.get("overall", {}).get("score"),
        verdicts.get("urlscan", {}).get("score"),
    ]
    for val in score_candidates:
        if isinstance(val, int):
            return val
    return None


def _is_malicious(result: dict[str, Any]) -> bool:
    verdicts = result.get("verdicts", {})
    checks = [
        verdicts.get("malicious"),
        verdicts.get("overall", {}).get("malicious"),
        verdicts.get("urlscan", {}).get("malicious"),
    ]
    return any(val is True for val in checks)


def fetch_urlscan(indicator: str, indicator_type: str, api_key: str | None) -> URLScanEvidence:
    ev = URLScanEvidence()

    if indicator_type == "ip":
        query = f"ip:{indicator} OR page.ip:{indicator}"
        gui_search = f"https://urlscan.io/search/#ip%3A{indicator}"
    elif indicator_type == "domain":
        query = f"domain:{indicator} OR page.domain:{indicator}"
        gui_search = f"https://urlscan.io/search/#domain%3A{indicator}"
    elif indicator_type == "url":
        query = f'task.url:"{indicator}" OR page.url:"{indicator}"'
        encoded_url = quote(f'"{indicator}"')
        gui_search = f"https://urlscan.io/search/#task.url%3A{encoded_url}"
    else:
        ev.error = f"Tipo de indicador não suportado no URLScan: {indicator_type}"
        return ev
        
    # Salva o link de busca logo no início como fallback
    ev.sample_result = gui_search

    headers: dict[str, str] = {"accept": "application/json"}
    if api_key:
        headers["API-Key"] = api_key

    try:
        response = requests.get(
            f"{URLSCAN_BASE_URL}/search/",
            headers=headers,
            params={"q": query, "size": 5},
            timeout=DEFAULT_TIMEOUT,
        )
    except requests.RequestException as exc:
        ev.error = f"Falha de conexão com URLScan: {exc}"
        return ev

    if response.status_code == 429:
        ev.error = "Rate limit do URLScan excedido."
        return ev

    if response.status_code >= 400:
        ev.error = f"Erro URLScan HTTP {response.status_code}: {response.text[:180]}"
        return ev

    try:
        payload = response.json()
    except ValueError:
        ev.error = "Resposta inválida do URLScan (JSON malformado)."
        return ev

    results = payload.get("results", []) or []
    ev.total_results = len(results)
    if not results:
        ev.error = "Sem resultados recentes no URLScan."
        return ev

    highest_score: int | None = None
    for item in results:
        score = _extract_score(item)
        if score is not None:
            highest_score = score if highest_score is None else max(highest_score, score)

        if _is_malicious(item):
            ev.malicious_hits += 1
        elif score is not None and score > 0:
            ev.suspicious_hits += 1

    ev.highest_score = highest_score
    api_link = results[0].get("result")
    if api_link:
        ev.sample_result = api_link.replace("/api/v1/", "/")
        
    if results:
        ev.server_location = results[0].get("page", {}).get("country")
        ev.resolved_ip = results[0].get("page", {}).get("ip")
        
    ev.available = True
    return ev


def classify(vt: VirusTotalEvidence, us: URLScanEvidence) -> tuple[str, str]:
    reasons: list[str] = []

    vt_signal_malicious = vt.malicious >= 3
    vt_signal_suspicious = vt.malicious > 0 or vt.suspicious > 0

    us_score = us.highest_score if us.highest_score is not None else -100
    us_signal_malicious = us.malicious_hits > 0 or us_score >= 70
    us_signal_suspicious = us.suspicious_hits > 0 or us_score > 0

    if vt.available:
        vt_info = f"VirusTotal: {vt.malicious} maliciosos, {vt.suspicious} suspeitos, {vt.harmless} harmless."
        if vt.creation_date:
            vt_info += f" Criado em: {vt.creation_date}."
        if vt.registrar:
            vt_info += f" Registrante: {vt.registrar}."
        reasons.append(vt_info)
    elif vt.error:
        reasons.append(f"VirusTotal indisponível: {vt.error}")

    if us.available:
        us_info = (
            f"URLScan: {us.malicious_hits} hits maliciosos, {us.suspicious_hits} suspeitos, "
            f"score máximo {us.highest_score if us.highest_score is not None else 'N/A'}."
        )
        if us.server_location:
            us_info += f" Hospedado em (país): {us.server_location}."
        if us.resolved_ip:
            us_info += f" IP do servidor: {us.resolved_ip}."
        reasons.append(us_info)
    elif us.error:
        reasons.append(f"URLScan indisponível: {us.error}")

    if vt_signal_malicious or us_signal_malicious:
        return "malicioso", " ".join(reasons)
    if vt_signal_suspicious or us_signal_suspicious:
        return "suspeito", " ".join(reasons)

    if vt.available or us.available:
        return "seguro", " ".join(reasons)

    return (
        "suspeito",
        "Sem dados suficientes nas duas fontes para afirmar segurança. " + " ".join(reasons),
    )


def investigate(indicator: str, vt_api_key: str, urlscan_api_key: str | None) -> InvestigationReport:
    indicator_type = detect_indicator_type(indicator)
    vt = fetch_virustotal(indicator, indicator_type, vt_api_key)
    us = fetch_urlscan(indicator, indicator_type, urlscan_api_key)
    classification, explanation = classify(vt, us)
    return InvestigationReport(
        indicator=indicator,
        indicator_type=indicator_type,
        classification=classification,
        explanation=explanation,
        virustotal=vt,
        urlscan=us,
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Investiga reputação de IP/domínio/URL usando VirusTotal e URLScan "
            "e classifica como seguro/suspeito/malicioso."
        )
    )
    parser.add_argument("indicator", help="IP, domínio ou URL para investigar.")
    parser.add_argument(
        "--output",
        choices=["text", "json"],
        default="text",
        help="Formato de saída (padrão: text).",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    vt_api_key = os.getenv("VIRUSTOTAL_API_KEY")
    urlscan_api_key = os.getenv("URLSCAN_API_KEY")

    if not vt_api_key:
        print(
            "Erro: defina VIRUSTOTAL_API_KEY no ambiente antes de executar.",
            file=sys.stderr,
        )
        return 2

    try:
        report = investigate(args.indicator, vt_api_key, urlscan_api_key)
    except InvestigationError as exc:
        print(f"Erro de investigação: {exc}", file=sys.stderr)
        return 1

    if args.output == "json":
        print(json.dumps(report.to_dict(), ensure_ascii=False, indent=2))
        return 0

    print(f"Indicador: {report.indicator}")
    print(f"Tipo: {report.indicator_type}")
    print(f"Classificação: {report.classification}")
    print(f"Explicação: {report.explanation}")

    if report.virustotal.link:
        print(f"Link VirusTotal: {report.virustotal.link}")
    if report.urlscan.sample_result:
        print(f"Exemplo URLScan: {report.urlscan.sample_result}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
