# 🛡️ Webhook de Análise de Ameaças

Webhook que recebe indicadores de comprometimento (IP, domínio ou hash), consulta a API do VirusTotal, gera um resumo de risco com IA (Gemini + mapeamento MITRE ATT&CK) e produz automaticamente um relatório de incidente de segurança.

## Arquitetura

```
┌─────────────────┐     ┌──────────────┐     ┌──────────────┐     ┌──────────────────┐
│  SIEM / Firewall│────▶│   Webhook    │────▶│  VirusTotal  │     │   Relatório      │
│  / Analista     │     │   (FastAPI)  │     │   API v3     │     │   de Incidente   │
└─────────────────┘     └──────┬───────┘     └──────┬───────┘     │   (.md)          │
                               │                    │              └────────▲─────────┘
                               │              dados normalizados           │
                               │                    │                      │
                               │              ┌─────▼──────┐              │
                               └─────────────▶│  Gemini IA │──────────────┘
                                              │  (resumo)  │
                                              └────────────┘
```

## Pré-requisitos

- **Python 3.11+**
- Chave de API do **VirusTotal** — [obter aqui](https://www.virustotal.com/gui/my-apikey)
- Chave de API do **Gemini** — [obter aqui](https://aistudio.google.com/apikey)

## Instalação

```bash
# 1. Clone ou copie o projeto
cd webhook-incidente

# 2. Crie o ambiente virtual
python -m venv .venv
# Windows:
.venv\Scripts\activate
# Linux/Mac:
source .venv/bin/activate

# 3. Instale as dependências
pip install -r requirements.txt

# 4. Configure as variáveis de ambiente
copy .env.example .env   # Windows
# cp .env.example .env   # Linux/Mac

# 5. Edite o .env com suas chaves
```

## Uso

### Iniciar o servidor

```bash
# Importa variáveis do .env
python -c "import config"

# Inicia o servidor
uvicorn main:app --reload --port 8000
```

O servidor estará disponível em `http://localhost:8000`.

### Enviar um indicador para análise

**Exemplo com IP:**

```bash
curl -X POST http://localhost:8000/webhook/analisar \
  -H "Content-Type: application/json" \
  -d '{
    "indicador": "8.8.8.8",
    "origem": "Firewall Palo Alto",
    "analista": "João Silva",
    "observacoes": "IP detectado em múltiplas tentativas de conexão na porta 443."
  }'
```

**Exemplo com Domínio:**

```bash
curl -X POST http://localhost:8000/webhook/analisar \
  -H "Content-Type: application/json" \
  -d '{
    "indicador": "example.com",
    "origem": "Proxy Corporativo",
    "analista": "Reinaldo César",
    "observacoes": "Domínio identificado em requisição DNS suspeita."
  }'
```

**Exemplo com hash (SHA-256):**

```bash
curl -X POST http://localhost:8000/webhook/analisar \
  -H "Content-Type: application/json" \
  -d '{
    "indicador": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
    "origem": "Antivírus Corporativo",
    "analista": "Maria Souza",
    "observacoes": "Hash extraído de arquivo suspeito encontrado em estação de trabalho."
  }'
```

### Resposta

```json
{
  "id_incidente": "INC-20261126-A1B2C3D4",
  "indicador": "8.8.8.8",
  "tipo_indicador": "ip",
  "resumo_risco": "O IP 8.8.8.8 pertence ao Google (AS15169)...",
  "classificacao": "INFORMATIVO",
  "mitre_attack": [],
  "caminho_relatorio": "relatorios/INC-20261126-A1B2C3D4.md",
  "data_analise": "2026-11-26T12:00:00+00:00"
}
```

### Documentação interativa

Acesse a UI do Swagger em: `http://localhost:8000/docs`

## Com Docker

```bash
docker build -t webhook-ameacas .
docker run -p 8000:8000 --env-file .env webhook-ameacas
```

## Estrutura do Projeto

```
webhook-incidente/
├── main.py                 # Servidor FastAPI (webhook)
├── virustotal_client.py    # Cliente da API do VirusTotal
├── ai_summarizer.py        # Resumo de risco com Gemini
├── report_generator.py     # Gerador de relatório de incidente
├── config.py               # Carregamento de variáveis de ambiente
├── requirements.txt        # Dependências Python
├── Dockerfile              # Build para container
├── .env.example            # Template de variáveis de ambiente
├── README.md               # Esta documentação
└── relatorios/             # Relatórios gerados (criado automaticamente)
```

## Formato do Relatório

Cada relatório gerado inclui:

1. **Informações Gerais** — ID, data, analista, origem, classificação
2. **Indicador de Comprometimento (IoC)** — tipo e valor
3. **Resumo Executivo de Risco** — gerado pela IA com base nos dados do VT + táticas MITRE ATT&CK
4. **Dados Técnicos** — estatísticas de detecção e detalhes do VirusTotal
5. **Recomendações de Resposta** — checklist de ações sugeridas
6. **Observações** — notas do analista
7. **Cadeia de Custódia** — registro das fontes de evidência
8. **Aprovação e Encerramento** — campos para revisão humana

## Classificações de Risco

| Nível          | Critério                                                     |
|----------------|--------------------------------------------------------------|
| 🔴 CRÍTICO     | Ampla detecção por engines, malware conhecido, ameaça ativa  |
| 🟠 ALTO        | Detecção significativa, comportamento suspeito confirmado    |
| 🟡 MÉDIO       | Algumas detecções, pode ser falso positivo                   |
| 🟢 BAIXO       | Poucas ou nenhuma detecção, baixo risco aparente             |
| 🔵 INFORMATIVO | Sem detecção, indicador provavelmente benigno                |
