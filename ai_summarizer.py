"""
Resumidor de risco com IA (Gemini)
===================================
Recebe dados normalizados do VirusTotal e devolve um resumo de risco
estruturado, pronto para compor o relatório de incidente.
"""

import asyncio
import json
import logging
from typing import Any

import httpx

logger = logging.getLogger("ai_summarizer")

_GEMINI_MODELS = [
    "gemini-3.8-flash",
    "gemini-3.1-flash-lite",
    "gemini-3.5-flash",
    "gemini-3.7-flash",
    "gemini-3-flash-preview",
    "gemini-4-hydrogen",
]
_GEMINI_URL_TEMPLATE = (
    "https://generativelanguage.googleapis.com/v1beta/models/"
    "{model}:generateContent"
)

_SYSTEM_PROMPT = """\
Você é um Analista Sênior de SOC / Resposta a Incidentes (Blue Team). Sua tarefa
é analisar os dados de inteligência de ameaças fornecidos (vindos do VirusTotal)
e produzir um resumo executivo de risco em português brasileiro.

Regras:
1. Baseie-se EXCLUSIVAMENTE nos dados fornecidos no JSON do VirusTotal. Não invente dados ausentes.
2. Seja objetivo, claro e profissional (adequado para auditoria e registro de incidentes).
3. Classifique o risco como: CRÍTICO, ALTO, MÉDIO, BAIXO ou INFORMATIVO.
4. Justifique a classificação com base nas detecções, reputação e contexto do indicador.
5. Mapeie possíveis táticas/técnicas do MITRE ATT&CK relacionadas ao comportamento identificado (ou retorne lista vazia [] se o indicador for benigno/informativo).
6. Liste recomendações práticas de resposta e contenção (máximo 5 itens).

Responda EXCLUSIVAMENTE em JSON com esta estrutura:
{
  "resumo": "<texto de 3-4 parágrafos descrevendo a ameaça e o veredito>",
  "classificacao": "<CRÍTICO|ALTO|MÉDIO|BAIXO|INFORMATIVO>",
  "mitre_attack": ["<ID e Tática/Técnica - breve justificativa>", ...],
  "recomendacoes": ["<ação 1>", "<ação 2>", ...]
}
"""


class AISummarizer:
    """Gera resumos de risco usando a API Gemini."""

    def __init__(self, api_key: str, timeout: float = 20.0):
        self._api_key = api_key
        self._timeout = timeout

    async def resumir(
        self,
        indicador: str,
        tipo: str,
        dados_virustotal: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Envia os dados do VirusTotal para a IA e retorna o resumo
        estruturado (resumo, classificacao, recomendacoes).
        """
        prompt_usuario = (
            f"Analise o seguinte indicador de comprometimento (IoC):\n\n"
            f"**Indicador:** `{indicador}`\n"
            f"**Tipo:** {tipo}\n\n"
            f"**Dados do VirusTotal:**\n"
            f"```json\n{json.dumps(dados_virustotal, indent=2, ensure_ascii=False)}\n```\n\n"
            f"Produza o resumo de risco conforme as regras do sistema."
        )

        payload = {
            "system_instruction": {
                "parts": [{"text": _SYSTEM_PROMPT}]
            },
            "contents": [
                {"role": "user", "parts": [{"text": prompt_usuario}]}
            ],
            "generationConfig": {
                "temperature": 0.3,
                "responseMimeType": "application/json",
            },
        }

        resposta = None
        ultimo_erro: Exception | None = None

        async with httpx.AsyncClient(timeout=self._timeout) as client:
            for tentativa in range(2):
                for model in _GEMINI_MODELS:
                    url = f"{_GEMINI_URL_TEMPLATE.format(model=model)}?key={self._api_key}"
                    logger.info("🤖  Solicitando resumo de risco à IA (%s)…", model)
                    try:
                        resp = await client.post(url, json=payload)
                        if resp.status_code in (404, 429, 500, 502, 503, 504):
                            logger.warning(
                                "Modelo %s indisponível (HTTP %s); tentando fallback.",
                                model,
                                resp.status_code,
                            )
                            ultimo_erro = httpx.HTTPStatusError(
                                f"HTTP {resp.status_code} para {model}",
                                request=resp.request,
                                response=resp,
                            )
                            continue
                        resp.raise_for_status()
                        resposta = resp.json()
                        break
                    except httpx.HTTPError as exc:
                        logger.warning("Falha ao chamar %s: %s", model, exc)
                        ultimo_erro = exc

                if resposta is not None:
                    break
                if tentativa == 0:
                    await asyncio.sleep(2.0)

        if resposta is None:
            raise RuntimeError(
                f"Todos os modelos Gemini falharam. Último erro: {ultimo_erro}"
            )
        texto = (
            resposta.get("candidates", [{}])[0]
            .get("content", {})
            .get("parts", [{}])[0]
            .get("text", "{}")
        )

        try:
            resultado = json.loads(texto)
            resultado.setdefault("mitre_attack", [])
            resultado.setdefault("recomendacoes", [])
        except json.JSONDecodeError:
            logger.warning("Resposta da IA não é JSON válido; usando fallback.")
            resultado = {
                "resumo": texto,
                "classificacao": "INDETERMINADO",
                "mitre_attack": [],
                "recomendacoes": ["Realizar análise manual."],
            }

        logger.info(
            "📊  Classificação de risco: %s", resultado.get("classificacao")
        )
        return resultado
