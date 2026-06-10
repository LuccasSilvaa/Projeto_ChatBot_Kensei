import os
import streamlit as st
import requests
from dotenv import load_dotenv

load_dotenv()

# Importa a função principal e a classe de erro do SEU projeto atual!
from security_investigator import investigate, InvestigationError

# Wrapper com cache (duração de 1 hora) para economizar limites das APIs externas
@st.cache_data(ttl=3600, show_spinner=False)
def cached_investigate(indicator, _vt_key, _us_key):
    return investigate(indicator, _vt_key, _us_key)

# Configuração da página do Streamlit
st.set_page_config(page_title="CyberSec AI Agent")

col1, col2 = st.columns([4, 1])
with col1:
    st.title("CyberSec AI Agent")
with col2:
    st.write("") # Espaçamento para alinhar verticalmente
    if st.button("Limpar Histórico"):
        st.session_state.messages = []
        st.rerun()

st.write("Insira um IP, domínio ou URL para análise. O motor de Threat Intelligence realizará a varredura e o modelo de IA fornecerá o veredito.")

# Carrega as chaves de API diretamente do ambiente de forma segura (.env)
vt_key = os.getenv("VIRUSTOTAL_API_KEY")
urlscan_key = os.getenv("URLSCAN_API_KEY")

# Modelo de IA fixo
ollama_model = "llama3"

if not vt_key:
    st.warning("A chave do VirusTotal não foi encontrada. Verifique se o arquivo `.env` está configurado corretamente com a variável `VIRUSTOTAL_API_KEY`.")
    st.stop()

# Inicializa o histórico do chat na sessão
if "messages" not in st.session_state:
    st.session_state.messages = []

# Desenha as mensagens antigas na tela
for message in st.session_state.messages:
    with st.chat_message(message["role"]):
        st.markdown(message["content"])

# Caixa de entrada de texto (Chat)
if prompt := st.chat_input("Ex: google.com, 8.8.8.8 ou example.com"):
    # Mostra a mensagem do usuário
    st.session_state.messages.append({"role": "user", "content": prompt})
    with st.chat_message("user"):
        st.markdown(prompt)

    # Mostra a resposta da IA
    with st.chat_message("assistant"):
        # 1. Barra de status passo a passo, substituindo o spinner básico
        with st.status("Iniciando investigação...", expanded=True) as status:
            try:
                status.update(label="Consultando bases de Threat Intelligence (VirusTotal e URLScan)...", state="running")
                report = cached_investigate(prompt, vt_key, urlscan_key)
                
                status.update(label="Analisando evidências e gerando relatório com Inteligência Artificial...", state="running")
                ai_prompt = f"""
                Você é um analista de segurança cibernética sênior.
                Acabamos de investigar o indicador: '{prompt}'.
                Aqui estão os dados brutos encontrados pelo nosso motor de Threat Intelligence:
                - Classificação técnica: {report.classification}
                - Detalhes da evidência: {report.explanation}
                
                Com base nessas informações, elabore um relatório detalhado e profissional em português.
                O relatório deve ser estruturado nos seguintes tópicos:
                1. Resumo Executivo: Veredito claro informando se é seguro acessar ou se há riscos. Destaque imediatamente se for um domínio suspeitamente novo.
                2. Análise Técnica: Explicação detalhada baseada nos dados (País de hospedagem, data de criação do domínio e detecções).
                3. Recomendações: Ações recomendadas. Se for um e-commerce/site de compras com criação recente, alerte enfaticamente sobre o alto risco de fraude/golpe.
                """
                
                # 3. Pede para o Ollama local gerar a resposta
                ollama_url = "http://localhost:11434/api/generate"
                payload = {"model": ollama_model, "prompt": ai_prompt, "stream": False}
                res = requests.post(ollama_url, json=payload)
                
                if res.status_code == 404:
                    erro_api = res.json().get("error", "")
                    raise Exception(f"Ollama retornou 404 ({erro_api}).\nIsso significa que o modelo '{ollama_model}' não foi baixado completamente. Tente rodar 'ollama run {ollama_model}' no terminal e aguarde os 100%.")
                elif res.status_code != 200:
                    raise Exception(f"Erro {res.status_code} do Ollama: {res.text}")

                resposta_ia = res.json().get("response", "Erro ao ler resposta do Ollama.")
                
                status.update(label="Investigação concluída com sucesso!", state="complete", expanded=False)
                
            except InvestigationError as e:
                status.update(label="Falha na investigação", state="error")
                st.error(f"Não foi possível investigar: {e}")
                st.stop()
            except Exception as e:
                status.update(label="Erro no processamento da IA", state="error")
                st.error(f"Ocorreu um erro ao conectar com o Ollama: {e}\nCertifique-se de que o Ollama está rodando ('ollama run {ollama_model}').")
                st.stop()

        st.markdown(resposta_ia)
        st.session_state.messages.append({"role": "assistant", "content": resposta_ia})