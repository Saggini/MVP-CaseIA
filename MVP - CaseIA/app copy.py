from flask import (
    Flask,
    request,
    render_template,
    redirect,
    url_for,
    flash,
    jsonify,
    send_file,
    session,
)
from flask_mail import Mail, Message
from pymongo import MongoClient
from backend.config import MONGO_URI, DATABASE_NAME
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail, Header  # Certifique-se de importar Header
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash
from datetime import datetime, timedelta
import jwt
import secrets
import os
import logging
import csv
import pandas as pd
from werkzeug.utils import secure_filename
import openai
import bcrypt
import sendgrid
import re
from oauthlib.oauth2 import WebApplicationClient
import requests
from fpdf import FPDF  # Adicionado para exportação em PDF

# Permitir HTTP em ambiente de desenvolvimento
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

# Configurações do Flask
app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")


# Configuração do MongoDB
client = MongoClient("mongodb://localhost:27017/")
db = client["mydatabase"]
users_collection = db["users"]

# Adicionar coleção para armazenar os casos de teste gerados
test_cases_collection = db["test_cases"]


def store_test_cases(username, test_cases):
    """Armazena os casos de teste gerados no banco de dados para o usuário logado"""
    user = users_collection.find_one({"username": username})
    if user:
        test_cases_collection.insert_one(
            {
                "user_id": user["_id"],
                "test_cases": test_cases,
                "created_at": datetime.now(),
            }
        )


# API Key do SendGrid (NÃO COLOQUE DIRETO NO CÓDIGO)
load_dotenv()  # Carrega as variáveis do .env
SENDGRID_API_KEY = os.getenv("SENDGRID_API_KEY")
SENDGRID_FROM_EMAIL = os.getenv("SENDGRID_FROM_EMAIL", "sagginitechsuporte@outlook.com")

if not SENDGRID_API_KEY or not SENDGRID_FROM_EMAIL:
    raise ValueError(
        "SENDGRID_API_KEY ou SENDGRID_FROM_EMAIL não estão configurados corretamente."
    )


def gerar_token(email):
    """Gera um token JWT com prazo de expiração"""
    payload = {
        "email": email,
        "exp": datetime.utcnow() + timedelta(hours=1),  # Expira em 1 hora
    }
    # Geração do token utilizando a chave secreta do Flask
    token = jwt.encode(payload, app.config["SECRET_KEY"], algorithm="HS256")
    return token


def generate_reset_token(email):
    """Gera um token JWT para redefinição de senha"""
    payload = {
        "email": email,
        "exp": datetime.datetime.utcnow()
        + datetime.timedelta(hours=1),  # Expira em 1 hora
    }
    return jwt.encode(payload, app.secret_key, algorithm="HS256")


def enviar_email(destinatario, token):
    """Envia um e-mail de recuperação de senha"""
    token = gerar_token(destinatario)  # Usa o e-mail real do usuário
    reset_link = f"http://127.0.0.1:5000/reset-password/{token}"
    # Aponta para a rota do Flask
    mensagem = Mail(
        from_email=SENDGRID_FROM_EMAIL,
        to_emails=destinatario,
        subject="Recuperação de Senha - CaseIA",
        html_content=f"""
            <p>Olá,</p>
            <p>Clique no link abaixo para redefinir sua senha:</p>
            <a href="{reset_link}">{reset_link}</a>
            <p>Se você não solicitou isso, ignore este e-mail.</p>
        """,
    )
    # Adicionar cabeçalhos personalizados
    mensagem.add_header(Header("X-Priority", "1"))  # Alta prioridade
    mensagem.add_header(Header("X-MSMail-Priority", "High"))
    mensagem.add_header(Header("Importance", "High"))

    try:
        sg = SendGridAPIClient(SENDGRID_API_KEY)
        response = sg.send(mensagem)
        return response.status_code == 202  # Status 202 significa enviado com sucesso
    except Exception as e:
        return False


# Configurações da OpenAI
openai.api_key = os.getenv("OPENAI_API_KEY")

# Definindo as pastas para o upload
UPLOAD_FOLDER = "uploads"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}

# Dados gerados de teste (simulação)
generated_test_results = []


# Função para verificar extensões de arquivo permitidas
def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


# Configuração do cliente OAuth2 para o Google
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
GOOGLE_DISCOVERY_URL = os.getenv("GOOGLE_DISCOVERY_URL")
client = WebApplicationClient(GOOGLE_CLIENT_ID)


def get_google_provider_cfg():
    return requests.get(GOOGLE_DISCOVERY_URL).json()


@app.route("/login_google")
def login_google():
    google_provider_cfg = get_google_provider_cfg()
    authorization_endpoint = google_provider_cfg["authorization_endpoint"]

    request_uri = client.prepare_request_uri(
        authorization_endpoint,
        redirect_uri=os.getenv("REDIRECT_URI"),
        scope=["openid", "email", "profile"],
    )
    return redirect(request_uri)


@app.route("/api/auth/google/callback")
def callback():
    code = request.args.get("code")
    google_provider_cfg = get_google_provider_cfg()
    token_endpoint = google_provider_cfg["token_endpoint"]

    token_url, headers, body = client.prepare_token_request(
        token_endpoint,
        authorization_response=request.url,
        redirect_url=os.getenv("REDIRECT_URI"),
        code=code,
    )
    token_response = requests.post(
        token_url,
        headers=headers,
        data=body,
        auth=(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET),
    )

    client.parse_request_body_response(token_response.text)

    userinfo_endpoint = google_provider_cfg["userinfo_endpoint"]
    uri, headers, body = client.add_token(userinfo_endpoint)
    userinfo_response = requests.get(uri, headers=headers, data=body)

    if userinfo_response.json().get("email_verified"):
        unique_id = userinfo_response.json()["sub"]
        users_email = userinfo_response.json()["email"]
        picture = userinfo_response.json()["picture"]
        users_name = userinfo_response.json()["given_name"]

        session["username"] = users_name
        session["email"] = users_email
        flash("Login com Google realizado com sucesso!", "success")
        return redirect(url_for("index"))
    else:
        flash("Falha ao autenticar com o Google.", "danger")
        return redirect(url_for("login"))


# Rotas
@app.route("/")
def landing():
    return render_template("landing.html", aria_label="Página inicial")


@app.route("/index")
def index():
    if "username" in session:
        return render_template(
            "index.html", username=session["username"], aria_label="Página principal"
        )
    return redirect(url_for("login"))


@app.route("/tests_manuais")
def tests_manuais():
    return render_template("tests_manuais.html", aria_label="Testes manuais")


@app.route("/tests_automatizados")
def tests_automatizados():
    return render_template(
        "tests_automatizados.html", aria_label="Testes automatizados"
    )


@app.route("/cadastro", methods=["GET", "POST"])
def cadastro():
    if request.method == "POST":
        first_name = request.form.get("first_name")
        last_name = request.form.get("last_name")
        email = request.form.get("email")
        username = request.form.get("username")
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")

        # Verificar se o e-mail já está cadastrado
        if users_collection.find_one({"email": email}):
            flash("E-mail já cadastrado.", "danger")
            return redirect(url_for("cadastro"))

        # Verificar se o e-mail já está cadastrado
        if users_collection.find_one({"username": username}):
            flash("Usuário já cadastrado.", "danger")
            return redirect(url_for("cadastro"))

        # Verificar se as senhas coincidem
        if password != confirm_password:
            flash("As senhas não coincidem.", "danger")
            return redirect(url_for("cadastro"))

        # Criptografar a senha
        hashed_password = generate_password_hash(password, method="pbkdf2:sha256")

        # Criar novo usuário
        new_user = {
            "first_name": first_name,
            "last_name": last_name,
            "email": email,
            "username": username,
            "password": hashed_password,
            "created_at": datetime.now(),
        }

        users_collection.insert_one(new_user)
        flash("Cadastro realizado com sucesso!", "success")
        return redirect(url_for("login"))

    return render_template("cadastro.html", aria_label="Página de cadastro")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        # Busca o usuário no banco
        user = users_collection.find_one({"username": username})
        if user:
            try:
                # Verificar a senha com bcrypt
                if bcrypt.checkpw(
                    password.encode("utf-8"), user["password"].encode("utf-8")
                ):
                    session["username"] = username
                    flash("Login realizado com sucesso!", "success")
                    return render_template("login.html", aria_label="Página de login")
                else:
                    flash("Credenciais inválidas, tente novamente.", "danger")
            except ValueError:
                flash(
                    "Erro ao verificar a senha. Por favor, redefina sua senha.",
                    "danger",
                )
        else:
            flash("Credenciais inválidas, tente novamente.", "danger")

        return render_template("login.html", aria_label="Página de login")

    return render_template("login.html", aria_label="Página de login")


@app.route("/logout")
def logout():
    session.pop("username", None)
    return redirect(url_for("landing"))


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    """Rota para solicitação de recuperação de senha"""
    if request.method == "POST":
        email = request.form.get("email")
        user = users_collection.find_one({"email": email})  # Busca o usuário no banco

        if user:
            # Criar um token fake (no real, você deve gerar um JWT ou hash)
            token = "token12345"
            if enviar_email(email, token):
                flash("Link de recuperação enviado para o seu e-mail!", "success")
            else:
                flash("Erro ao enviar e-mail. Tente novamente mais tarde.", "danger")
        else:
            flash("E-mail não encontrado.", "danger")

    return render_template("forgot_password.html", aria_label="Recuperação de senha")


# Função para gerar token de recuperação
def generate_reset_token(email):
    payload = {
        "email": email,
        "exp": datetime.datetime.utcnow()
        + datetime.timedelta(hours=1),  # Expira em 1 hora
    }
    return jwt.encode(payload, app.config["SECRET_KEY"], algorithm="HS256")


# Rota para redefinir a senha
@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    try:
        # Decodifica o token
        data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
        email = data.get("email")  # Extrai o e-mail do token
    except jwt.ExpiredSignatureError:
        flash("O link expirou. Solicite uma nova recuperação.", "danger")
        return redirect(url_for("forgot_password"))
    except jwt.InvalidTokenError:
        flash("Link inválido. Solicite novamente.", "danger")
        return redirect(url_for("forgot_password"))

    if request.method == "POST":
        new_password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")

        if new_password != confirm_password:
            flash("As senhas não coincidem. Tente novamente.", "danger")
            return redirect(request.url)

        # Corrigir o erro de salt inválido ao armazenar a senha
        hashed_password = bcrypt.hashpw(
            new_password.encode("utf-8"), bcrypt.gensalt()
        ).decode("utf-8")

        users_collection.update_one(
            {"email": email}, {"$set": {"password": hashed_password}}
        )

        flash("Senha redefinida com sucesso! Faça login.", "success")
        return redirect(url_for("login"))

    return render_template(
        "reset_password.html", token=token, aria_label="Redefinir senha"
    )

    # Função para limpar o texto do prompt


def limpar_texto(prompt):
    # Remover ** antes e depois de "Descrição:" e "Cenário:"
    prompt = re.sub(
        r"\*\*\s*(Descrição:|Cenário:)\s*\*\*", r"\1", prompt, flags=re.IGNORECASE
    )

    # Remover ** antes de "Dado que", "Quando", "E" e "Então"
    prompt = re.sub(
        r"\*\*\s*(Dado que|Quando|E|Então)\s*\*\*", r"\1", prompt, flags=re.IGNORECASE
    )

    # Remover *** antes de "Caso de Teste"
    prompt = re.sub(r"\*\*\s*(Caso de Teste)", r"\1", prompt, flags=re.IGNORECASE)

    # Remover ** no final do título do "Caso de Teste"
    prompt = re.sub(r"(Caso de Teste \d+: [^\n]*?)\s*\*\*\s*(?=\n|$)", r"\1", prompt)

    # Remover ### antes de "Caso de Teste"
    prompt = re.sub(r"\s*###\s*(Caso de Teste)", r"\1", prompt, flags=re.IGNORECASE)

    # Remover --- antes de "Caso de Teste"
    prompt = re.sub(r"\s*---\s*(Caso de Teste)", r"\1", prompt, flags=re.IGNORECASE)

    # Adicionar quebra de linha antes de "Cenário Positivo"
    prompt = re.sub(
        r"(?<!\n)\s*(Cenário Positivo:)", r"\n\n\1", prompt, flags=re.IGNORECASE
    )

    # Adicionar quebra de linha antes de "Cenário Negativo"
    prompt = re.sub(
        r"(?<!\n)\s*(Cenário Negativo:)", r"\n\n\1", prompt, flags=re.IGNORECASE
    )

    # Adicionar quebra de linha antes de "Cenário de Borda"
    prompt = re.sub(
        r"(?<!\n)\s*(Cenário de Borda:)", r"\n\n\1", prompt, flags=re.IGNORECASE
    )

    # Adicionar quebra de linha entre os casos de teste
    prompt = re.sub(r"(Caso de Teste \d+:)", r"\n\n\1", prompt)

    # Remover "- **" antes de "Dado que", "Quando", "E" e "Então"
    prompt = re.sub(
        r"- \*\*\s*(Dado que|Quando|E|Então)", r"\1", prompt, flags=re.IGNORECASE
    )

    # Remover "**" depois de "Dado que:", "Quando:" e "Então:"
    prompt = re.sub(
        r"(Dado que:|Quando:|Então:)\s*\*\*", r"\1", prompt, flags=re.IGNORECASE
    )

    # Remover "####" antes de "Descrição:" e "Cenário:"
    prompt = re.sub(
        r"\s*####\s*(Descrição:|Cenário:)", r"\1", prompt, flags=re.IGNORECASE
    )

    return prompt


@app.context_processor
def inject_vlibras():
    """Adiciona o script do VLibras ao contexto de todas as páginas."""
    vlibras_script = """
    <div vw class="enabled">
        <div vw-access-button class="active"></div>
        <div vw-plugin-wrapper>
            <div class="vw-plugin-top-wrapper"></div>
        </div>
    </div>
    <script src="https://vlibras.gov.br/app/vlibras-plugin.js"></script>
    <script>
        new window.VLibras.Widget('https://vlibras.gov.br/app');
    </script>
    """
    return dict(vlibras_script=vlibras_script)


@app.route("/check_email", methods=["GET"])
def check_email():
    """Verifica se o e-mail já está cadastrado no banco de dados."""
    email = request.args.get("email")
    if not email:
        return jsonify({"exists": False}), 400

    email_exists = users_collection.find_one({"email": email}) is not None
    return jsonify({"exists": email_exists})


@app.route("/check_username", methods=["GET"])
def check_username():
    """Verifica se o nome de usuário já está cadastrado no banco de dados."""
    username = request.args.get("username")
    if not username:
        return jsonify({"exists": False}), 400

    username_exists = users_collection.find_one({"username": username}) is not None
    return jsonify({"exists": username_exists})


@app.route("/generate_tests", methods=["POST"])
def generate_tests():
    try:
        # Receber os dados do formulário
        criteria = request.form.get("criteria")
        system_type = request.form.get("system_type")
        image = request.files.get("image")  # Obter a imagem do formulário

        # Validação dos dados
        if not criteria or not system_type:
            return jsonify({"error": "Por favor, preencha todos os campos!"}), 400

        image_url = None

        if image and allowed_file(image.filename):
            # Salvar a imagem
            filename = secure_filename(image.filename)
            image.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
            image_url = os.path.join(app.config["UPLOAD_FOLDER"], filename)

        # Construir o prompt com base no tipo de sistema
        if system_type == "Web":
            prompt = f"""
            Você é um especialista em testes de software para aplicações Web. Com base nos critérios de aceitação fornecidos abaixo, crie **casos de teste no formato BDD (Dado que, Quando, E, Então)** para validar funcionalidades de interfaces web.

            Cada caso de teste deve incluir:
            1. Título: No formato "Caso de Teste X: Nome da Funcionalidade ou Validação"
            2. Descrição: Explique claramente o que será validado (ex.: comportamento do botão, preenchimento de formulário, navegação entre páginas, etc.)
            3. Cenário: Descreva o fluxo no formato BDD com:
            - Dado que: Estado inicial da página ou sistema.
            - Quando: Ações do usuário (clicar, preencher campos, navegar, etc.).
            - Então: Resultados esperados (elementos visíveis, mensagens exibidas, redirecionamentos, etc.).

            ### **Regras para elaboração dos casos de teste:**
            - Inclua **validação de elementos da interface** (botões, campos de formulário, links, etc.).
            - Teste a **interatividade** (cliques, arrastar e soltar, pop-ups, tooltips, etc.).
            - Considere **testes de responsividade** (exibição em diferentes tamanhos de tela e dispositivos).
            - Valide o **comportamento em diferentes navegadores** (Chrome, Firefox, Edge, etc.).
            - Inclua **testes de acessibilidade** quando relevante (atalhos de teclado, uso por leitores de tela).

            ### **Cenários Alternativos:**
            - Cenários Positivos: Testes que validam o comportamento esperado em condições normais.
            - Cenários Negativos: Testes que validam o comportamento do sistema em condições de erro ou uso inadequado.
            - Cenários de Borda: Testes que validam o comportamento do sistema em condições extremas ou limites.

            Critérios de aceitação:
            {criteria}
            """
        elif system_type == "API":
            prompt = f"""
            Você é um especialista em testes de software para testes de APIs. Baseado nos critérios de aceitação fornecidos abaixo, crie **casos de teste no formato BDD (Dado que, Quando, E, Então)** para validar endpoints de APIs REST.

            Cada caso de teste deve incluir:
            1. Título: No formato "Caso de Teste X: Nome da Validação ou Endpoint Testado"
            2. Descrição: Explique claramente o que o teste pretende validar (ex.: status code, retorno do body, autenticação, etc.)
            3. Cenário: Escreva os passos no formato BDD considerando:
            - **Validação de Status Codes** (200, 201, 400, 403, 404, 500, etc.)
            - **Verificação do Conteúdo do Body** (dados retornados, mensagens de erro, etc.)
            - **Checagem de Headers**, autenticação e tokens (quando aplicável)
            - **Validação de Esquema** (confirme se o formato dos dados no body está correto)

            ### **Cenários Alternativos:**
            - Cenários Positivos: Testes que validam o comportamento esperado em condições normais.
            - Cenários Negativos: Testes que validam o comportamento do sistema em condições de erro ou uso inadequado.
            - Cenários de Borda: Testes que validam o comportamento do sistema em condições extremas ou limites.

            Critérios de aceitação:
            {criteria}
            """
        elif system_type == "Mobile":
            prompt = f"""
            Você é um especialista em testes de software para testes mobile. Baseado nos critérios de aceitação fornecidos abaixo, gere **casos de teste detalhados** para aplicativos móveis (iOS e Android), focando em funcionalidades específicas e na experiência do usuário.

            Cada caso de teste deve incluir:
            1. Título: No formato "Caso de Teste X: Nome da Funcionalidade ou Fluxo Testado"
            2. Objetivo: Descreva claramente o que o teste pretende validar e qual comportamento esperado.
            3. Pré-condições: Liste os requisitos necessários antes de executar o teste, como estar logado no app, permissões concedidas, ou conexão com a internet.
            4. Cenário: Escreva os passos no formato BDD (Dado que, Quando, E, Então), considerando interações típicas de dispositivos móveis.
            5. Resultado Esperado: Explique o que deve acontecer após a execução do teste, incluindo mensagens exibidas, mudanças visuais ou respostas do sistema.

            ### **Cenários Alternativos:**
            - Cenários Positivos: Testes que validam o comportamento esperado em condições normais.
            - Cenários Negativos: Testes que validam o comportamento do sistema em condições de erro ou uso inadequado.
            - Cenários de Borda: Testes que validam o comportamento do sistema em condições extremas ou limites.

            Critérios de aceitação:
            {criteria}
            """
        elif system_type == "Desktop":
            prompt = f"""
            Você é um especialista em testes de software para testes desktop. Baseado nos critérios de aceitação fornecidos abaixo, gere **casos de teste detalhados** para aplicações desktop (Windows, macOS, Linux), focando em funcionalidades específicas.

            Cada caso de teste deve incluir:
            1. Título: No formato "Caso de Teste X: Nome da Funcionalidade"
            2. Descrição: Explique claramente o objetivo do teste e o comportamento esperado
            3. Cenário: Escreva os passos no formato BDD (Dado que, Quando, E, Então), descrevendo ações e resultados esperados

            ### **Cenários Alternativos:**
            - Cenários Positivos: Testes que validam o comportamento esperado em condições normais.
            - Cenários Negativos: Testes que validam o comportamento do sistema em condições de erro ou uso inadequado.
            - Cenários de Borda: Testes que validam o comportamento do sistema em condições extremas ou limites.

            Critérios de aceitação:
            {criteria}
            """

        else:
            return jsonify({"error": "Tipo de sistema inválido!"}), 400

        # Se uma imagem foi carregada, adicionar ao prompt
        if image_url:
            prompt += f"\nAlém disso, a imagem fornecida ajuda a melhorar a assertividade na geração dos casos de teste. Ela pode ser vista aqui: {image_url}"

        #######################DESCOMENTAR APOS REMOVER BRANCH E TESTES##########################################

        # Chamada para a API do ChatGPT
        response = openai.ChatCompletion.create(
            model="gpt-4o-mini",  # Ou qualquer modelo que você prefira
            messages=[
                {
                    "role": "system",
                    "content": "Você é um especialista em automação de testes.",
                },
                {"role": "user", "content": prompt},
            ],
            max_tokens=1000,
        )

        # Processar a resposta da API
        generated_text = response["choices"][0]["message"]["content"]

        ########################DESCOMENTAR APOS REMOVER BRANCH E TESTES#############################

        ##Remover apos branhch de testes ####################################################################################
        # Bloco de código para testes gerados manualmente (substituir pela integração com a API futuramente)
        # Código de teste gerado manualmente para fins de simulação
        # generated_text = """Caso de Teste 1: Adicionar Produto ao Carrinho
        # Descrição: Este caso de teste valida a funcionalidade de adicionar um produto ao carrinho de compras e garante que o total atualizado seja exibido corretamente na interface.

        # Cenário:

        # - Dado que o usuário está na página de um produto com informações detalhadas e um botão "Adicionar ao Carrinho".
        # - Quando o usuário clica no botão "Adicionar ao Carrinho".
        # - E o usuário visualiza os produtos no carrinho.
        # - Então o sistema deve exibir uma mensagem de confirmação de que o produto foi adicionado ao carrinho.

        # Cenários Alternativos:

        # Cenário Positivo:
        # - Dado que o usuário está logado e na página de um produto.
        # - Quando o usuário adiciona o produto ao carrinho.
        # - Então o carrinho deve ser atualizado corretamente.

        # Cenário Negativo:
        # - Dado que o usuário não está logado.
        # - Quando o usuário tenta adicionar um produto ao carrinho.
        # - Então o sistema deve solicitar que o usuário faça login.

        # Cenário de Borda:
        # - Dado que o usuário adiciona o máximo de itens permitidos ao carrinho.
        # - Quando o usuário tenta adicionar mais um item.
        # - Então o sistema deve exibir uma mensagem de erro."""
        ##Remover apos branhch de testes ####################################################################################

        ##Remover apos branhch de testes ####################################################################################
        # Limpar o texto do prompt antes de enviar para a OpenAI
        generated_text = limpar_texto(generated_text)
        ##Remover apos branhch de testes ####################################################################################

        ## Supondo que a resposta da API seja uma lista de casos de teste no formato esperado
        ## Você pode precisar ajustar esta parte dependendo do formato da resposta da API
        test_cases = generated_text.split("\n\n")
        ## Supondo que cada caso de teste esteja separado por duas quebras de linha
        for i, test_case in enumerate(
            test_cases, start=len(generated_test_results) + 1
        ):
            # Dividir o caso de teste em partes
            parts = test_case.split("\n")
            title = parts[0].strip() if len(parts) > 0 else ""
            step_action = " ".join(parts[1:-1]).strip() if len(parts) > 2 else ""
            step_expected_result = parts[-1].strip() if len(parts) > 1 else ""

            generated_test_results.append(
                {
                    "Title": title,
                    "Step Action": step_action,
                    "Step Expected Result": step_expected_result,
                }
            )

        # Print para verificar o conteúdo de generated_test_results
        print("Generated Test Results:")
        for result in generated_test_results:
            print(result)
        # Print para verificar o conteúdo de generated_test_results

        ########################DESCOMENTAR APOS REMOVER BRANCH E TESTES##############################################
        # Limpar o texto do prompt antes de enviar para a OpenAI
        # prompt = limpar_texto(prompt)
        ############################DESCOMENTAR APOS REMOVER BRANCH E TESTES##########################################

        # Armazenar os casos de teste gerados no banco de dados
        if "username" in session:
            store_test_cases(session["username"], generated_text)

        return jsonify({"test_cases": generated_text}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/generate_automated_tests", methods=["POST"])
def generate_automated_tests():
    try:
        # Receber os dados do formulário
        criteria = request.form.get("criteria")
        system_type = request.form.get("system_type")
        framework = request.form.get("framework")
        image = request.files.get("image")  # Obter a imagem do formulário

        # Validação dos dados
        if not criteria or not system_type or not framework:
            return jsonify({"error": "Por favor, preencha todos os campos!"}), 400

        image_url = None

        if image and allowed_file(image.filename):
            # Salvar a imagem
            filename = secure_filename(image.filename)
            image.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
            image_url = os.path.join(app.config["UPLOAD_FOLDER"], filename)

        # Construir o prompt com base no tipo de sistema e framework
        if system_type == "Web":
            if framework == "Cypress":
                prompt = f"""
                Você é um especialista em testes de software para aplicações Web. Com base nos critérios de aceitação fornecidos abaixo, crie **casos de teste automatizados para um sistema web usando o {framework}**.
                O teste deve ser escrito em JavaScript/TypeScript e utilizar boas práticas, como uso de interceptações e comandos customizados.
                Utilize as melhores práticas do framework e certifique-se de incluir asserções adequadas.
                Critérios de aceitação:
                {criteria}
                """
            elif framework == "Robot Framework":
                prompt = f"""
                Você é um especialista em testes de software para aplicações Web. Baseado nos critérios de aceitação fornecidos abaixo, crie **casos de teste automatizados para um sistema web usando o {framework}**.
                O teste deve validar os critérios de aceite, utilizar palavras-chave reutilizáveis e capturar screenshots.
                Utilize as melhores práticas do framework e certifique-se de incluir asserções adequadas.
                Critérios de aceitação:
                {criteria}
                """
            elif framework == "Playwright":
                prompt = f"""
                Você é um especialista em testes de software para aplicações Web. Baseado nos critérios de aceitação fornecidos abaixo, crie **casos de teste automatizados para um sistema web usando o {framework}**.
                Utilize TypeScript e boas práticas do framework. O teste deve incluir espera por elementos, capturas de tela em falhas e uso de Page Object Model (POM).
                Critérios de aceitação:
                {criteria}
                """
            elif framework == "Selenium":
                prompt = f"""
                Você é um especialista em testes de software para aplicações Web. Com base nos critérios de aceitação fornecidos abaixo, crie **casos de teste automatizados para um sistema web usando o {framework}**.
                Utilize Python/Java (especificar linguagem) e Page Object Model. O teste deve incluir ações de clique, entrada de dados e validações de elementos.
                Utilize as melhores práticas do framework e certifique-se de incluir asserções adequadas.
                Critérios de aceitação:
                {criteria}
                """
            else:
                return jsonify({"error": "Framework inválido!"}), 400

        elif system_type == "API":
            if framework == "Robot Framework":
                prompt = f"""
                Você é um especialista em testes de software para testes de APIs. Baseado nos critérios de aceitação fornecidos abaixo, crie **casos de teste automatizados para uma API usando o {framework}**.
                O teste deve validar endpoints, status codes, e conteúdo do body.
                Utilize as melhores práticas do framework e certifique-se de incluir asserções adequadas.
                Critérios de aceitação:
                {criteria}
                """
            elif framework == "Postman":
                prompt = f"""
                Você é um especialista em testes de software para testes de APIs. Baseado nos critérios de aceitação fornecidos abaixo, crie **casos de teste automatizados para uma API usando o {framework}**.
                O teste deve validar endpoints, status codes, e conteúdo do body.
                Utilize as melhores práticas do framework e certifique-se de incluir asserções adequadas.
                Critérios de aceitação:
                {criteria}
                """
            else:
                return jsonify({"error": "Framework inválido!"}), 400

        elif system_type == "Mobile":
            if framework == "Appium":
                prompt = f"""
                Você é um especialista em testes de software para testes mobile. Baseado nos critérios de aceitação fornecidos abaixo, gere **casos de teste automatizados no formato {framework}**.
                Utilize as melhores práticas do framework e certifique-se de incluir asserções adequadas.
                Critérios de aceitação:
                {criteria}
                """
            elif framework == "Robot Framework":
                prompt = f"""
                Você é um especialista em testes de software para testes mobile. Baseado nos critérios de aceitação fornecidos abaixo, gere **casos de teste automatizados no formato {framework}**.
                Utilize as melhores práticas do framework e certifique-se de incluir asserções adequadas.
                Critérios de aceitação:
                {criteria}
                """
            else:
                return jsonify({"error": "Framework inválido!"}), 400

        elif system_type == "Desktop":
            if framework == "Pywinauto":
                prompt = f"""
                Você é um especialista em testes de software para testes desktop. Baseado nos critérios de aceitação fornecidos abaixo, gere **casos de teste automatizados no formato {framework}**.
                Utilize as melhores práticas do framework e certifique-se de incluir asserções adequadas.
                Critérios de aceitação:
                {criteria}
                """
            elif framework == "Robot Framework":
                prompt = f"""
                Você é um especialista em testes de software para testes desktop. Baseado nos critérios de aceitação fornecidos abaixo, gere **casos de teste automatizados no formato {framework}**.
                Utilize as melhores práticas do framework e certifique-se de incluir asserções adequadas.
                Critérios de aceitação:
                {criteria}
                """
            else:
                return jsonify({"error": "Framework inválido!"}), 400

        else:
            return jsonify({"error": "Tipo de sistema inválido!"}), 400

        # Se uma imagem foi carregada, adicionar ao prompt
        if image_url:
            prompt += f"\nAlém disso, a imagem fornecida ajuda a melhorar a assertividade na geração dos casos de teste. Ela pode ser vista aqui: {image_url}"

        # Chamada para a API do ChatGPT
        response = openai.ChatCompletion.create(
            model="gpt-4o-mini",  # Ou qualquer modelo que você prefira
            messages=[
                {
                    "role": "system",
                    "content": "Você é um especialista em automação de testes.",
                },
                {"role": "user", "content": prompt},
            ],
            max_tokens=1000,
        )

        # Processar a resposta da API
        generated_text = response["choices"][0]["message"]["content"]

        # Limpar o texto do prompt antes de enviar para a OpenAI
        generated_text = limpar_texto(generated_text)

        # Supondo que a resposta da API seja uma lista de casos de teste no formato esperado
        test_cases = generated_text.split("\n\n")
        for i, test_case in enumerate(
            test_cases, start=len(generated_test_results) + 1
        ):
            parts = test_case.split("\n")
            title = parts[0].strip() if len(parts) > 0 else ""
            step_action = " ".join(parts[1:-1]).strip() if len(parts) > 2 else ""
            step_expected_result = parts[-1].strip() if len(parts) > 1 else ""

            generated_test_results.append(
                {
                    "Title": title,
                    "Step Action": step_action,
                    "Step Expected Result": step_expected_result,
                }
            )

        # Armazenar os casos de teste gerados no banco de dados
        if "username" in session:
            store_test_cases(session["username"], generated_text)

        return jsonify({"test_cases": generated_text}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/save_edited_tests", methods=["POST"])
def save_edited_tests():
    try:
        edited_tests = request.json.get("edited_tests")
        print("Edited Tests Received:", edited_tests)  # Log para depuração
        global generated_test_results

        # Processar o texto editado para convertê-lo em uma lista de dicionários
        test_cases = edited_tests.split("\n\n")
        generated_test_results = []
        for test_case in test_cases:
            parts = test_case.split("\n")
            title = parts[0].strip() if len(parts) > 0 else ""
            description = parts[1].strip() if len(parts) > 1 else ""
            steps = parts[2:] if len(parts) > 2 else []

            step_action = []
            step_expected_result = []

            for step in steps:
                step = step.strip()
                if (
                    step.startswith("- Dado que")
                    or step.startswith("- Quando")
                    or step.startswith("- E")
                ):
                    step_action.append(step)
                elif step.startswith("- Então"):
                    step_expected_result.append(step)

            generated_test_results.append(
                {
                    "Title": title,
                    "Step Action": "\n".join(step_action),
                    "Step Expected Result": "\n".join(step_expected_result),
                }
            )

        return jsonify({"message": "Casos de teste salvos com sucesso!"}), 200
    except Exception as e:
        print("Error:", str(e))  # Log para depuração
        return jsonify({"error": str(e)}), 500


@app.route("/export_csv", methods=["GET"])
def export_csv():
    # Definindo o caminho do arquivo
    file_path = os.path.join(app.config["UPLOAD_FOLDER"], "test_cases.csv")

    # Criando o arquivo CSV com o modelo de colunas
    with open(file_path, mode="w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(["Title", "Step Action", "Step Expected Result"])

        current_title = None
        dado_que, quando, e, step_expected = [], [], [], []

        for test_case in generated_test_results:
            title = test_case["Title"].strip()
            step_action = test_case["Step Action"].strip()
            step_result = test_case["Step Expected Result"].strip()

            # Se encontrar um novo caso de teste, grava o anterior
            if title.startswith("Caso de Teste"):
                if current_title:
                    writer.writerow(
                        [
                            current_title,
                            "\n".join(dado_que + quando + e),
                            "\n".join(step_expected),
                        ]
                    )

                # Inicia um novo caso de teste
                current_title = title
                dado_que, quando, e, step_expected = [], [], [], []

            # Diagnóstico
            print(f"Step Action: {step_action}")

            # Captura os passos de ação
            action_lower = step_action.lower()
            if action_lower.startswith("- dado que"):
                dado_que.append(step_action)
            elif action_lower.startswith("- quando"):
                quando.append(step_action)
            elif action_lower.startswith("- e"):
                e.append(step_action)

            # Captura os resultados esperados
            if step_result.lower().startswith("- então"):
                step_expected.append(step_result)

        # Grava o último caso de teste processado
        if current_title and (dado_que or quando or e or step_expected):
            writer.writerow(
                [
                    current_title,
                    "\n".join(dado_que + quando + e),
                    "\n".join(step_expected),
                ]
            )

    return send_file(file_path, as_attachment=True)


@app.route("/export_pdf", methods=["GET"])
def export_pdf():
    class PDFWithTOC(FPDF):
        def __init__(self):
            super().__init__()
            self.toc = []  # Lista de tuplas (titulo, pagina)

        def add_case_to_toc(self, title):
            self.toc.append((title, self.page_no()))

        def insert_toc(self):
            self.add_page()
            self.set_font("Arial", style="B", size=16)
            self.cell(0, 10, "Sumário", ln=True, align="C")
            self.ln(10)

            self.set_font("Arial", size=12)
            for title, page in self.toc:
                self.cell(
                    0, 10, f"{title} ............................. {page}", ln=True
                )

    pdf = PDFWithTOC()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font("Arial", size=12)

    # Adicionar logo
    logo_path = os.path.join("static", "img", "LOGO-1.PNG-removebg-preview.png")
    if os.path.exists(logo_path):
        pdf.image(logo_path, x=10, y=8, w=30)
    pdf.ln(30)

    # Título principal
    pdf.set_font("Arial", style="B", size=16)
    pdf.cell(0, 10, txt="Casos de Teste Gerados", ln=True, align="C")
    pdf.ln(10)

    if not generated_test_results:
        pdf.set_font("Arial", size=12)
        pdf.cell(0, 10, txt="Nenhum caso de teste foi gerado.", ln=True)
    else:
        for index, test_case in enumerate(generated_test_results, start=1):
            pdf.add_page()

            title = f"Caso de Teste {index}: {test_case.get('Title', 'Sem Título')}"
            pdf.add_case_to_toc(title)

            # Título do caso de teste
            pdf.set_font("Arial", style="B", size=14)
            pdf.cell(0, 10, txt=title, ln=True)

            pdf.ln(5)
            pdf.set_font("Arial", size=12)
            pdf.multi_cell(0, 10, txt="Descrição:")
            descricao = test_case.get("Description", "Descrição não fornecida.")
            pdf.multi_cell(0, 10, txt=descricao)

            pdf.ln(5)
            pdf.set_font("Arial", size=12)
            pdf.multi_cell(0, 10, txt="Cenário:")

            acao = test_case.get("Step Action", "")
            resultado = test_case.get("Step Expected Result", "")
            steps = []

            if acao:
                steps += [step.strip() for step in acao.split("\n") if step.strip()]
            if resultado:
                steps += [
                    step.strip() for step in resultado.split("\n") if step.strip()
                ]

            for step in steps:
                pdf.multi_cell(0, 10, txt=f"- {step}")

            pdf.ln(10)

    # Inserir o sumário no início (segunda página)
    pdf.insert_toc()

    # Salvar o PDF
    file_path = os.path.join(app.config["UPLOAD_FOLDER"], "test_cases.pdf")
    pdf.output(file_path)

    return send_file(file_path, as_attachment=True)


@app.route("/historico")
def historico():
    return render_template("historico.html", aria_label="Histórico de testes")


@app.route("/api/historico", methods=["GET"])
def api_historico():
    if "username" not in session:
        return jsonify([])

    user = users_collection.find_one({"username": session["username"]})
    if not user:
        return jsonify([])

    # Obter os 10 últimos casos de teste gerados pelo usuário
    test_cases = (
        test_cases_collection.find({"user_id": user["_id"]})
        .sort("created_at", -1)
        .limit(10)
    )
    historico = [
        {"test_cases": tc["test_cases"], "created_at": tc["created_at"]}
        for tc in test_cases
    ]
    return jsonify(historico)


def detectar_formato(texto):
    gherkin_pattern = r"^(Feature:|Scenario:|Given |When |Then )"
    markdown_pattern = r"^(\#|\*|\-|\d\.)\s"

    if re.search(gherkin_pattern, texto, re.MULTILINE):
        return "gherkin"
    elif re.search(markdown_pattern, re.MULTILINE):
        return "markdown"
    else:
        return "texto_livre"


if __name__ == "__main__":
    # Verificar se a chave da API está configurada
    if not openai.api_key:
        logging.error(
            "A chave da API da OpenAI não está configurada. Configure a variável de ambiente OPENAI_API_KEY."
        )
        exit(1)

    # Garantir que a pasta de upload exista
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)

    app.run(debug=True)
