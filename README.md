# CaseIA

Uma ferramenta automatizada que utiliza a API do ChatGPT para gerar casos de teste no formato BDD (Behavior-Driven Development) com base nos requisitos do sistema fornecidos pelo usuário.

## Funcionalidades

- Geração automática de casos de teste BDD.
- Suporte para vários tipos de sistemas: Web, API, Mobile e Desktop.
- Exportação de casos de teste gerados nos formatos **CSV** e **XLSX**.
- Interface simples e intuitiva para entrada de dados e visualização dos resultados.

---

## Como Rodar o Projeto

### 1. Instale as dependências

Certifique-se de ter o Python 3.7+ instalado em sua máquina. Em seguida, execute o comando abaixo para instalar as dependências necessárias:

```bash
pip install -r requirements.txt


> **Nota**: Se o arquivo `requirements.txt` ainda não existir, crie-o listando as dependências:
>
> ```
> flask
> openai
> ```

### 2. Configure a API Key da OpenAI

1. Obtenha sua chave de API na [OpenAI](https://platform.openai.com/).

2. No arquivo `app.py`, localize a linha:

   ```python
   openai.api_key = "SUA_API_KEY_AQUI"
   ```

3. Substitua `"SUA_API_KEY_AQUI"` pela sua chave de API.

### 3. Execute o servidor

No terminal, execute o seguinte comando:

```bash
python app.py
```

O servidor Flask será iniciado e poderá ser acessado no navegador através do endereço:

```
http://127.0.0.1:5000
```

---

## Estrutura do Projeto

```plaintext
CaseIA/
├── app.py               # Arquivo principal da aplicação
├── services.py          # Funções auxiliares e integrações
├── verificar_modelo_do_meu_ChatGPT.py  # Verificação do modelo
├── templates/           # Arquivos HTML
├── static/              # Arquivos estáticos (CSS, JS, imagens)
├── README.md            # Documentação do projeto
├── .gitignore           # Arquivo para ignorar arquivos no controle de versão
├── requirements.txt     # Dependências do projeto
└── __pycache__/         # Arquivos temporários do Python (ignorado pelo .gitignore)

```

---

## Contribuição

Contribuições são bem-vindas! Siga os passos abaixo para contribuir:

1. Realize um fork do repositório.

2. Crie uma nova branch:

   ```bash
   git checkout -b minha-feature
   ```

3. Realize as alterações e faça commit:

   ```bash
   git commit -m "Minha nova feature"
   ```

4. Envie as alterações:

   ```bash
   git push origin minha-feature
   ```

5. Abra um Pull Request no repositório original.

---

## Licença

Este projeto está licenciado sob a licença MIT. Consulte o arquivo `LICENSE` para mais informações.

---

## Contato

Se tiver dúvidas ou sugestões, entre em contato:

- **Email**: [sagginitech@gmail.com](mailto\:sagginitech@gmail.com)
- **LinkedIn**: [Seu Perfil](https://www.linkedin.com/in/briansagini/)
