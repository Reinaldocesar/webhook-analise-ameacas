"""
Webhook de Análise de Ameaças — Ponto de Entrada
=================================================
Recebe IP, domínio ou hash suspeito via POST, consulta o VirusTotal,
pede para a IA resumir o nível de risco (incluindo MITRE ATT&CK) e
gera automaticamente o rascunho do relatório de incidente.
"""

import os
import re
import logging
from datetime import datetime, timezone
from contextlib import asynccontextmanager
from uuid import uuid4

from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from virustotal_client import VirusTotalClient
from ai_summarizer import AISummarizer
from report_generator import ReportGenerator

# ---------------------------------------------------------------------------
# Configuração de logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
)
logger = logging.getLogger("webhook")

# ---------------------------------------------------------------------------
# Lifecycle — inicializa e encerra clientes de forma limpa
# ---------------------------------------------------------------------------
vt_client: VirusTotalClient | None = None
ai_summarizer: AISummarizer | None = None
report_gen: ReportGenerator | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global vt_client, ai_summarizer, report_gen

    vt_api_key = os.getenv("VIRUSTOTAL_API_KEY")
    gemini_api_key = os.getenv("GEMINI_API_KEY")

    if not vt_api_key:
        raise RuntimeError(
            "Variável de ambiente VIRUSTOTAL_API_KEY não configurada."
        )
    if not gemini_api_key:
        raise RuntimeError(
            "Variável de ambiente GEMINI_API_KEY não configurada."
        )

    vt_client = VirusTotalClient(api_key=vt_api_key)
    ai_summarizer = AISummarizer(api_key=gemini_api_key)
    report_gen = ReportGenerator(output_dir="relatorios")

    logger.info("✅  Serviço inicializado com sucesso.")
    yield
    logger.info("🛑  Encerrando serviço.")


# ---------------------------------------------------------------------------
# App FastAPI
# ---------------------------------------------------------------------------
app = FastAPI(
    title="Webhook de Análise de Ameaças",
    description=(
        "Recebe indicadores de comprometimento (IoC), consulta o VirusTotal, "
        "gera resumo de risco com IA e produz relatório de incidente."
    ),
    version="1.0.0",
    lifespan=lifespan,
)


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------
class IndicadorRequest(BaseModel):
    """Payload recebido pelo webhook."""

    indicador: str = Field(
        ...,
        description="IP, domínio ou hash (MD5/SHA-1/SHA-256) a ser analisado.",
        examples=["8.8.8.8", "example.com", "44d88612fea8a8f36de82e1278abb02f"],
    )
    origem: str = Field(
        default="manual",
        description="Origem do alerta (ex.: SIEM, firewall, manual).",
    )
    analista: str = Field(
        default="Sistema Automatizado",
        description="Nome do analista ou sistema que disparou a consulta.",
    )
    observacoes: str = Field(
        default="",
        description="Observações adicionais sobre o indicador.",
    )


class IndicadorResponse(BaseModel):
    """Resposta devolvida ao chamador."""

    id_incidente: str
    indicador: str
    tipo_indicador: str
    resumo_risco: str
    classificacao: str
    mitre_attack: list[str] = Field(default_factory=list)
    caminho_relatorio: str
    data_analise: str


_DOMINIO_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
)


# ---------------------------------------------------------------------------
# Utilitário para detectar tipo de indicador
# ---------------------------------------------------------------------------
def detectar_tipo(indicador: str) -> str:
    """Retorna 'ip', 'dominio', 'hash_md5', 'hash_sha1', 'hash_sha256' ou 'desconhecido'."""
    indicador = indicador.strip()

    # IPv4 simples
    partes = indicador.split(".")
    if len(partes) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in partes):
        return "ip"

    # Hashes por comprimento
    if all(c in "0123456789abcdefABCDEF" for c in indicador):
        tamanho = len(indicador)
        if tamanho == 32:
            return "hash_md5"
        if tamanho == 40:
            return "hash_sha1"
        if tamanho == 64:
            return "hash_sha256"

    # Domínio válido (FQDN)
    if len(indicador) <= 253 and _DOMINIO_RE.match(indicador):
        return "dominio"

    return "desconhecido"


# ---------------------------------------------------------------------------
# Endpoint principal — webhook
# ---------------------------------------------------------------------------
@app.post(
    "/webhook/analisar",
    response_model=IndicadorResponse,
    summary="Analisa um IP, domínio ou hash suspeito",
    tags=["Webhook"],
)
async def analisar_indicador(payload: IndicadorRequest):
    """
    Fluxo completo:
    1. Identifica se o indicador é IP, domínio ou hash.
    2. Consulta a API do VirusTotal.
    3. Envia os dados brutos para a IA gerar resumo de risco e táticas MITRE ATT&CK.
    4. Gera o relatório de incidente em Markdown.
    5. Retorna o resumo e o caminho do relatório.
    """
    indicador_limpo = payload.indicador.strip()
    id_incidente = f"INC-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{uuid4().hex[:8].upper()}"
    tipo = detectar_tipo(indicador_limpo)

    if tipo == "desconhecido":
        raise HTTPException(
            status_code=400,
            detail=(
                f"Indicador '{indicador_limpo}' não é um IPv4, domínio válido "
                "nem um hash MD5/SHA-1/SHA-256 reconhecido."
            ),
        )

    if tipo == "dominio":
        indicador_limpo = indicador_limpo.lower()

    logger.info(
        "📥  Novo indicador recebido: %s (tipo=%s, origem=%s)",
        indicador_limpo,
        tipo,
        payload.origem,
    )

    # 1. Consulta VirusTotal
    try:
        dados_vt = await vt_client.consultar(indicador_limpo, tipo)
    except Exception as exc:
        logger.error("Erro ao consultar VirusTotal: %s", exc)
        raise HTTPException(
            status_code=502, detail=f"Falha na consulta ao VirusTotal: {exc}"
        )

    # 2. Resumo de risco via IA
    try:
        resumo = await ai_summarizer.resumir(
            indicador=indicador_limpo,
            tipo=tipo,
            dados_virustotal=dados_vt,
        )
    except Exception as exc:
        logger.error("Erro ao gerar resumo de risco: %s", exc)
        resumo = {
            "resumo": "Não foi possível gerar o resumo automático de risco.",
            "classificacao": "INDETERMINADO",
            "mitre_attack": [],
            "recomendacoes": ["Realizar análise manual dos dados do VirusTotal."],
        }

    # 3. Gerar relatório de incidente
    try:
        caminho_relatorio = report_gen.gerar(
            id_incidente=id_incidente,
            indicador=indicador_limpo,
            tipo=tipo,
            origem=payload.origem,
            analista=payload.analista,
            observacoes=payload.observacoes,
            dados_virustotal=dados_vt,
            resumo_ia=resumo,
        )
    except Exception as exc:
        logger.error("Erro ao gerar relatório: %s", exc)
        caminho_relatorio = "erro_ao_gerar_relatorio"

    logger.info(
        "✅  Análise concluída — %s → %s | Relatório: %s",
        indicador_limpo,
        resumo.get("classificacao", "N/A"),
        caminho_relatorio,
    )

    return IndicadorResponse(
        id_incidente=id_incidente,
        indicador=indicador_limpo,
        tipo_indicador=tipo,
        resumo_risco=resumo.get("resumo", ""),
        classificacao=resumo.get("classificacao", "INDETERMINADO"),
        mitre_attack=resumo.get("mitre_attack", []),
        caminho_relatorio=caminho_relatorio,
        data_analise=datetime.now(timezone.utc).isoformat(),
    )


# ---------------------------------------------------------------------------
# Health-check
# ---------------------------------------------------------------------------
@app.get("/health", tags=["Infra"])
async def health():
    return {"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()}
