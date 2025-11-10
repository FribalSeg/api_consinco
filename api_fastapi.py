from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel
from typing import Optional, Any, List
import os
import secrets
from gerenciar_token import GerenciadorToken
import uvicorn

# Configuração da API
app = FastAPI(
    title="API SQL Consinco",
    description="API para executar consultas SQL via GerenciadorToken",
    version="1.0.0"
)

# Modelo de requisição
class SQLQuery(BaseModel):
    sql_query: str

# Modelo de resposta
class SQLResponse(BaseModel):
    success: bool
    data: Optional[Any] = None  # Alterado de dict para Any para aceitar lista ou dict
    error: Optional[str] = None

# Configurações do gerenciador (pode ser movido para variáveis de ambiente)
URL_LOGIN = os.getenv('URL_LOGIN')
NOME = os.getenv('NOME')
SENHA = os.getenv('SENHA')
PORT= os.getenv('PORT', 8000)

assert NOME is not None, "NOME não está definido nas variáveis de ambiente"
assert SENHA is not None, "SENHA não está definido nas variáveis de ambiente"
assert URL_LOGIN is not None, "URL_LOGIN não está definido nas variáveis de ambiente"

# Configuração de autenticação Basic
security = HTTPBasic()

# Credenciais válidas
VALID_USERNAME = os.getenv('VALID_USERNAME')
VALID_PASSWORD = os.getenv('VALID_PASSWORD')

assert VALID_USERNAME is not None, "VALID_USERNAME não está definido nas variáveis de ambiente"
assert VALID_PASSWORD is not None, "VALID_PASSWORD não está definido nas variáveis de ambiente"

# Inicializar gerenciador
gerenciador = GerenciadorToken(URL_LOGIN, NOME, SENHA)

# Dependência de autenticação
def verificar_autenticacao(credentials: HTTPBasicCredentials = Depends(security)):
    """
    Verifica se as credenciais Basic Auth são válidas.
    """
    # Comparação segura para evitar timing attacks
    correct_username = secrets.compare_digest(credentials.username, VALID_USERNAME)
    correct_password = secrets.compare_digest(credentials.password, VALID_PASSWORD)

    if not (correct_username and correct_password):
        raise HTTPException(
            status_code=401,
            detail="Credenciais inválidas",
            headers={"WWW-Authenticate": "Basic"},
        )

    return credentials.username

# Endpoint de saúde
@app.get("/health")
def health_check():
    """Endpoint para verificar se a API está funcionando"""
    return {"status": "ok", "message": "API está funcionando"}

# Endpoint principal para executar SQL
@app.post("/sql/query", response_model=SQLResponse)
def executar_sql(
    query: SQLQuery,
    username: str = Depends(verificar_autenticacao)
):
    """
    Executa uma consulta SQL usando o GerenciadorToken.

    Requer autenticação via Basic Auth

    Exemplo de requisição:
    ```json
    {
        "sql_query": "SELECT * FROM dual"
    }
    ```
    """
    try:
        # Executar consulta SQL
        resultado = gerenciador.consulta_sql(query.sql_query)

        if resultado is not None:
            return SQLResponse(
                success=True,
                data=resultado,
                error=None
            )
        else:
            return SQLResponse(
                success=False,
                data=None,
                error="Falha ao executar a consulta SQL"
            )

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Erro ao executar consulta: {str(e)}"
        )

# Endpoint para verificar status do token
@app.get("/token/status")
def status_token(username: str = Depends(verificar_autenticacao)):
    """
    Retorna o status do token de autenticação do Consinco.

    Requer autenticação via Basic Auth
    """
    try:
        status = gerenciador.status_token()
        return {
            "success": True,
            "status": status
        }
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Erro ao obter status do token: {str(e)}"
        )

# Endpoint raiz
@app.get("/")
def root():
    """Endpoint raiz com informações da API"""
    return {
        "message": "API SQL Consinco",
        "version": "1.0.0",
        "endpoints": {
            "health": "/health",
            "sql_query": "/sql/query (POST)",
            "token_status": "/token/status (GET)"
        },
        "authentication": "Basic Auth"
    }

# Executar servidor
if __name__ == "__main__":
    # Para desenvolvimento
    uvicorn.run(
        "api_fastapi:app",
        host="0.0.0.0",
        port=int(PORT),
        reload=True
    )
