# CaseIA

Descubra como o CaseIA pode transformar seu dia a dia como QA! Com recursos avançados e uma interface intuitiva, nossa plataforma gera casos de teste automaticamente, ajudando você a garantir a qualidade do seu software de forma eficiente e escalável.

## Funcionalidades

- Geração automática de casos de teste com base nos critérios de aceite.
- Suporte a múltiplos tipos de sistemas, incluindo Web, API, Mobile e Desktop.
- Compatibilidade com diversos frameworks de automação, como Cypress, Playwright, Robot Framework e Selenium.
- Histórico completo dos casos de teste gerados para fácil acompanhamento.
- Exportação em CSV, permitindo o armazenamento e compartilhamento dos testes gerados.
- Interface intuitiva e fácil de usar, otimizando a entrada de dados e a visualização dos resultados.

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
