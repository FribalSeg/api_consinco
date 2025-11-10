FROM python:3.11-slim

# Definir diretório de trabalho
WORKDIR /app

# Copiar arquivos de dependências
COPY requirements.txt .

# Instalar dependências
RUN pip install --no-cache-dir -r requirements.txt

# Copiar código da aplicação
COPY . .

# Criar diretório para tokens
RUN mkdir -p /app/tokens

# Expor porta
EXPOSE 8000

# Comando para executar a aplicação
CMD ["uvicorn", "api_fastapi:app", "--host", "0.0.0.0", "--port", "8000"]
