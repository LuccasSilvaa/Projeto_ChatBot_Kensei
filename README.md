# 🕵️‍♂️ CyberSec AI Agent

O **CyberSec AI Agent** é uma ferramenta open-source de Threat Intelligence que automatiza a investigação de Indicadores de Comprometimento (IoCs), como IPs, Domínios e URLs. Ele combina motores de varredura consolidados no mercado com Inteligência Artificial local para gerar laudos técnicos e executivos em segundos.

## 🚀 Funcionalidades

- **Varredura em Múltiplas Fontes:** Integração nativa com as APIs do **VirusTotal** e **URLScan**.
- **Análise Avançada de Domínios:** Extrai data de criação, empresa registrante (Registrar), país de hospedagem e IP de resolução.
- **Inteligência Artificial (Privacy-First):** Utiliza o **Ollama (Llama 3)** rodando localmente na máquina do analista, garantindo que os dados sensíveis da investigação não sejam enviados para APIs de IA em nuvem de terceiros.
- **Relatórios Executivos Automáticos:** A IA interpreta os dados brutos e gera um relatório profissional contendo:
  - Resumo Executivo (com destaque para riscos de phishing baseados na idade do domínio).
  - Análise Técnica.
  - Recomendações de Segurança.
- **Interface Web Moderna:** Painel limpo, responsivo e interativo construído com **Streamlit**.
- **Otimização de Quota:** Sistema de cache integrado para poupar requisições redundantes nas APIs.

---

## 🛠️ Tecnologias Utilizadas

- **Linguagem:** Python 3
- **Interface:** Streamlit
- **Integrações (APIs):** VirusTotal API v3, URLScan API v1
- **IA/LLM:** Ollama (Llama 3)
- **Gerenciamento de Ambiente:** python-dotenv

---

## ⚙️ Pré-requisitos

Antes de começar, você precisará ter instalado em sua máquina:
- [Python 3.8+](https://www.python.org/downloads/)
- [Ollama](https://ollama.com/) (para rodar a IA localmente)

E precisará de chaves de API (gratuitas) nos seguintes serviços:
- Conta no [VirusTotal](https://www.virustotal.com/)
- Conta no [URLScan.io](https://urlscan.io/)

---

## 📥 Instalação e Configuração

1. **Clone o repositório:**
   ```bash
   git clone https://github.com/SEU-USUARIO/nome-do-repositorio.git
   cd nome-do-repositorio
   ```

2. **Instale as dependências Python:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure as Variáveis de Ambiente:**
   - Copie o arquivo de exemplo para criar o seu `.env`:
     ```bash
     cp .env.example .env
     ```
   - Edite o arquivo `.env` e insira suas chaves do VirusTotal e URLScan.

4. **Baixe o modelo de IA no Ollama:**
   ```bash
   ollama run llama3
   ```
   *(Isso fará o download do modelo Llama 3. Você pode fechar com `Ctrl+D` após o download atingir 100%).*

---

## ▶️ Como Usar

Com o Ollama rodando em background na sua máquina, inicie a interface do Streamlit:

```bash
streamlit run app.py
```

O seu navegador padrão abrirá automaticamente na porta `8501`. Basta inserir o IP, URL ou domínio desejado na caixa de chat e aguardar a emissão do laudo!