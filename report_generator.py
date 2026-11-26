"""
Gerador de Relatório de Incidente
==================================
Produz um relatório de incidente de segurança em Markdown, seguindo
boas práticas de comunicação escrita e registro de evidências.
"""

import os
import logging
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger("report_generator")

# Mapeamento de classificação para emoji visual
_BADGE = {
    "CRÍTICO": "🔴",
    "ALTO": "🟠",
    "MÉDIO": "🟡",
    "BAIXO": "🟢",
    "INFORMATIVO": "🔵",
    "INDETERMINADO": "⚪",
}


class ReportGenerator:
    """Gera relatórios de incidente em formato Markdown."""

    def __init__(self, output_dir: str = "relatorios"):
        self._output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def gerar(
        self,
        id_incidente: str,
        indicador: str,
        tipo: str,
        origem: str,
        analista: str,
        observacoes: str,
        dados_virustotal: dict[str, Any],
        resumo_ia: dict[str, Any],
    ) -> str:
        """
        Gera o relatório completo e retorna o caminho do arquivo salvo.
        """
        agora = datetime.now(timezone.utc)
        classificacao = resumo_ia.get("classificacao", "INDETERMINADO")
        badge = _BADGE.get(classificacao, "⚪")

        conteudo = self._montar_relatorio(
            id_incidente=id_incidente,
            indicador=indicador,
            tipo=tipo,
            origem=origem,
            analista=analista,
            observacoes=observacoes,
            dados_vt=dados_virustotal,
            resumo_ia=resumo_ia,
            classificacao=classificacao,
            badge=badge,
            timestamp=agora,
        )

        nome_arquivo = f"{id_incidente}.md"
        caminho = os.path.join(self._output_dir, nome_arquivo)

        with open(caminho, "w", encoding="utf-8") as f:
            f.write(conteudo)

        logger.info("📄  Relatório salvo em: %s", caminho)
        return caminho

    # ------------------------------------------------------------------
    # Montagem do template
    # ------------------------------------------------------------------
    def _montar_relatorio(
        self,
        id_incidente: str,
        indicador: str,
        tipo: str,
        origem: str,
        analista: str,
        observacoes: str,
        dados_vt: dict[str, Any],
        resumo_ia: dict[str, Any],
        classificacao: str,
        badge: str,
        timestamp: datetime,
    ) -> str:
        recomendacoes = resumo_ia.get("recomendacoes", [])
        recomendacoes_md = "\n".join(
            f"- [ ] {r}" for r in recomendacoes
        ) or "- [ ] Nenhuma recomendação disponível."

        mitre = resumo_ia.get("mitre_attack", [])
        mitre_md = "\n".join(
            f"- {m}" for m in mitre
        ) or "_Nenhuma tática ou técnica maliciosa associada (indicador benigno/informativo)._"

        deteccoes_md = self._formatar_deteccoes(dados_vt)
        info_tecnica = self._formatar_info_tecnica(dados_vt)

        return f"""# {badge} Relatório de Incidente — {id_incidente}

> **Documento gerado automaticamente** pelo sistema de análise de ameaças.
> Revisão humana obrigatória antes de qualquer ação de resposta.

---

## 1. Informações Gerais

| Campo                | Valor                                           |
|----------------------|-------------------------------------------------|
| **ID do Incidente**  | `{id_incidente}`                                |
| **Data/Hora (UTC)**  | {timestamp.strftime('%d/%m/%Y %H:%M:%S')} UTC   |
| **Analista**         | {analista}                                      |
| **Origem do Alerta** | {origem}                                        |
| **Classificação**    | {badge} **{classificacao}**                     |

---

## 2. Indicador de Comprometimento (IoC)

| Campo          | Valor              |
|----------------|---------------------|
| **Indicador**  | `{indicador}`      |
| **Tipo**       | {tipo}             |

---

## 3. Resumo Executivo de Risco

{resumo_ia.get("resumo", "Resumo não disponível.")}

### 3.1 Possíveis Táticas e Técnicas (MITRE ATT&CK)

{mitre_md}

---

## 4. Dados Técnicos — VirusTotal

### 4.1 Estatísticas de Detecção

| Métrica            | Valor                                      |
|--------------------|---------------------------------------------|
| **Total Engines**  | {dados_vt.get("total_engines", "N/A")}     |
| **Malicioso**      | {dados_vt.get("malicioso", "N/A")}         |
| **Suspeito**       | {dados_vt.get("suspeito", "N/A")}          |
| **Inofensivo**     | {dados_vt.get("inofensivo", "N/A")}        |
| **Não Detectado**  | {dados_vt.get("nao_detectado", "N/A")}     |

{deteccoes_md}

### 4.2 Informações Adicionais

{info_tecnica}

---

## 5. Recomendações de Resposta

{recomendacoes_md}

---

## 6. Observações

{observacoes if observacoes else "_Nenhuma observação registrada._"}

---

## 7. Cadeia de Custódia e Evidências

| # | Evidência                                | Fonte             | Data/Hora                                      |
|---|------------------------------------------|--------------------|------------------------------------------------|
| 1 | Consulta à API do VirusTotal (v3)        | VirusTotal         | {timestamp.strftime('%d/%m/%Y %H:%M:%S')} UTC  |
| 2 | Resumo de risco gerado por IA (Gemini)   | Gemini API         | {timestamp.strftime('%d/%m/%Y %H:%M:%S')} UTC  |
| 3 | Relatório de incidente gerado            | Sistema Interno    | {timestamp.strftime('%d/%m/%Y %H:%M:%S')} UTC  |

---

## 8. Aprovação e Encerramento

| Campo                   | Valor                        |
|-------------------------|-------------------------------|
| **Status**              | 🟡 RASCUNHO — Pendente de revisão |
| **Revisado por**        | _Aguardando revisão_         |
| **Data de revisão**     | _Pendente_                   |
| **Aprovado por**        | _Aguardando aprovação_       |
| **Data de aprovação**   | _Pendente_                   |

---

> ⚠️ **Aviso Legal**: Este relatório foi gerado com auxílio de inteligência
> artificial e dados de fontes públicas (VirusTotal). As informações devem
> ser validadas por um analista de segurança antes de qualquer tomada de
> decisão. O conteúdo deste documento é confidencial e deve ser tratado
> conforme a política de classificação da informação vigente.

---
*Relatório gerado automaticamente em {timestamp.strftime('%d/%m/%Y às %H:%M:%S')} UTC*
"""

    # ------------------------------------------------------------------
    # Formatadores auxiliares
    # ------------------------------------------------------------------
    @staticmethod
    def _formatar_deteccoes(dados_vt: dict) -> str:
        """Formata a tabela de detecções dos engines populares."""
        resultados = dados_vt.get("resultados_populares", [])
        if not resultados:
            return ""

        linhas = ["### Detecções Relevantes", ""]
        linhas.append("| Engine | Resultado |")
        linhas.append("|--------|-----------|")
        for r in resultados:
            linhas.append(f"| {r['engine']} | `{r['resultado']}` |")
        linhas.append("")
        return "\n".join(linhas)

    @staticmethod
    def _formatar_info_tecnica(dados_vt: dict) -> str:
        """Monta detalhes técnicos conforme o tipo de indicador."""
        tipo = dados_vt.get("tipo", "")
        linhas = []

        if tipo == "ip":
            linhas.append(f"- **País:** {dados_vt.get('pais', 'N/A')}")
            linhas.append(f"- **AS Owner:** {dados_vt.get('as_owner', 'N/A')}")
            linhas.append(f"- **ASN:** {dados_vt.get('asn', 'N/A')}")
            linhas.append(f"- **Reputação:** {dados_vt.get('reputacao', 'N/A')}")
            tags = dados_vt.get("tags", [])
            if tags:
                linhas.append(f"- **Tags:** {', '.join(tags)}")
        elif tipo == "dominio":
            linhas.append(f"- **Registrar:** {dados_vt.get('registrar', 'N/A')}")
            linhas.append(f"- **Reputação:** {dados_vt.get('reputacao', 'N/A')}")
            categorias = dados_vt.get("categorias", {})
            if categorias:
                cats_unicas = sorted(set(categorias.values()))
                linhas.append(f"- **Categorias:** {', '.join(cats_unicas[:6])}")
            tags = dados_vt.get("tags", [])
            if tags:
                linhas.append(f"- **Tags:** {', '.join(tags)}")
        elif tipo == "arquivo":
            linhas.append(f"- **SHA-256:** `{dados_vt.get('sha256', 'N/A')}`")
            linhas.append(f"- **SHA-1:** `{dados_vt.get('sha1', 'N/A')}`")
            linhas.append(f"- **MD5:** `{dados_vt.get('md5', 'N/A')}`")
            linhas.append(f"- **Tipo de arquivo:** {dados_vt.get('tipo_arquivo', 'N/A')}")
            linhas.append(f"- **Tamanho:** {dados_vt.get('tamanho_bytes', 0):,} bytes")
            linhas.append(f"- **Assinatura digital:** {dados_vt.get('assinatura', 'N/A')}")
            nomes = dados_vt.get("nomes_conhecidos", [])
            if nomes:
                linhas.append(f"- **Nomes conhecidos:** {', '.join(nomes[:5])}")

        return "\n".join(linhas) if linhas else "_Sem informações adicionais._"
