"""
Cliente assíncrono para a API v3 do VirusTotal
===============================================
Suporta consultas de IP, domínios e hashes (MD5, SHA-1, SHA-256).
"""

import logging
from typing import Any

import httpx

logger = logging.getLogger("virustotal")

_BASE_URL = "https://www.virustotal.com/api/v3"

# Mapeamento tipo → endpoint VirusTotal
_ENDPOINT_MAP = {
    "ip": "/ip_addresses/{indicador}",
    "dominio": "/domains/{indicador}",
    "hash_md5": "/files/{indicador}",
    "hash_sha1": "/files/{indicador}",
    "hash_sha256": "/files/{indicador}",
}


class VirusTotalClient:
    """Encapsula chamadas à API do VirusTotal (v3)."""

    def __init__(self, api_key: str, timeout: float = 30.0):
        self._headers = {"x-apikey": api_key}
        self._timeout = timeout

    async def consultar(self, indicador: str, tipo: str) -> dict[str, Any]:
        """
        Consulta o VirusTotal e devolve um dicionário normalizado com
        os campos mais relevantes para a análise de risco.
        """
        endpoint_tpl = _ENDPOINT_MAP.get(tipo)
        if not endpoint_tpl:
            raise ValueError(f"Tipo de indicador não suportado: {tipo}")

        url = _BASE_URL + endpoint_tpl.format(indicador=indicador)

        async with httpx.AsyncClient(timeout=self._timeout) as client:
            logger.info("🔎  Consultando VirusTotal: %s", url)
            resp = await client.get(url, headers=self._headers)
            resp.raise_for_status()
            dados = resp.json()

        return self._normalizar(dados, tipo, indicador)

    # ------------------------------------------------------------------
    # Normalização de resposta
    # ------------------------------------------------------------------
    def _normalizar(
        self, dados: dict, tipo: str, indicador: str
    ) -> dict[str, Any]:
        """Extrai os campos essenciais da resposta bruta da API."""
        atributos = dados.get("data", {}).get("attributes", {})

        if tipo == "ip":
            return self._normalizar_ip(atributos, indicador)
        if tipo == "dominio":
            return self._normalizar_dominio(atributos, indicador)
        return self._normalizar_arquivo(atributos, indicador)

    @staticmethod
    def _extrair_stats(attr: dict) -> dict[str, int]:
        """Extrai contagens padronizadas de detecção dos engines."""
        stats = attr.get("last_analysis_stats", {})
        return {
            "total_engines": sum(stats.values()) if stats else 0,
            "malicioso": stats.get("malicious", 0),
            "suspeito": stats.get("suspicious", 0),
            "inofensivo": stats.get("harmless", 0),
            "nao_detectado": stats.get("undetected", 0),
        }

    def _normalizar_ip(
        self, attr: dict, indicador: str
    ) -> dict[str, Any]:
        return {
            "indicador": indicador,
            "tipo": "ip",
            "pais": attr.get("country", "N/A"),
            "as_owner": attr.get("as_owner", "N/A"),
            "asn": attr.get("asn", "N/A"),
            "reputacao": attr.get("reputation", "N/A"),
            **self._extrair_stats(attr),
            "votos_comunidade": attr.get("total_votes", {}),
            "whois": (attr.get("whois", "") or "")[:500],
            "tags": attr.get("tags", []),
            "ultima_analise": attr.get("last_analysis_date", "N/A"),
            "resultados_populares": self._top_deteccoes(attr),
        }

    def _normalizar_dominio(
        self, attr: dict, indicador: str
    ) -> dict[str, Any]:
        return {
            "indicador": indicador,
            "tipo": "dominio",
            "registrar": attr.get("registrar", "N/A"),
            "data_criacao": attr.get("creation_date", "N/A"),
            "reputacao": attr.get("reputation", "N/A"),
            "categorias": attr.get("categories", {}),
            **self._extrair_stats(attr),
            "votos_comunidade": attr.get("total_votes", {}),
            "whois": (attr.get("whois", "") or "")[:500],
            "tags": attr.get("tags", []),
            "ultima_analise": attr.get("last_analysis_date", "N/A"),
            "resultados_populares": self._top_deteccoes(attr),
        }

    def _normalizar_arquivo(
        self, attr: dict, indicador: str
    ) -> dict[str, Any]:
        nomes_conhecidos = attr.get("names", [])
        signers = attr.get("signature_info", {})

        return {
            "indicador": indicador,
            "tipo": "arquivo",
            "sha256": attr.get("sha256", "N/A"),
            "sha1": attr.get("sha1", "N/A"),
            "md5": attr.get("md5", "N/A"),
            "tamanho_bytes": attr.get("size", 0),
            "tipo_arquivo": attr.get("type_description", "N/A"),
            "magic": attr.get("magic", "N/A"),
            **self._extrair_stats(attr),
            "nomes_conhecidos": nomes_conhecidos[:10],
            "assinatura": signers.get("subject", "N/A") if signers else "N/A",
            "tags": attr.get("tags", []),
            "reputacao": attr.get("reputation", "N/A"),
            "primeira_submissao": attr.get("first_submission_date", "N/A"),
            "ultima_analise": attr.get("last_analysis_date", "N/A"),
            "resultados_populares": self._top_deteccoes(attr),
        }

    @staticmethod
    def _top_deteccoes(attr: dict, limite: int = 10) -> list[dict]:
        """Retorna as detecções mais relevantes (apenas as que flagaram)."""
        resultados = attr.get("last_analysis_results", {})
        detectados = [
            {"engine": nome, "resultado": info.get("result", "N/A")}
            for nome, info in resultados.items()
            if info.get("category") in ("malicious", "suspicious")
        ]
        return detectados[:limite]
