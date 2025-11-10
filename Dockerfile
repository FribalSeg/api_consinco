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

# Definir PYTHONPATH para garantir que os módulos sejam encontrados
ENV PYTHONPATH=/app

# Expor porta
EXPOSE 8001

# Comando para executar a aplicação
CMD ["python", "-m", "uvicorn", "api_fastapi:app", "--host", "0.0.0.0", "--port", "8001"]
