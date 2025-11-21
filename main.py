from fastapi import FastAPI, HTTPException, Depends
from fastapi.responses import RedirectResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel
from typing import Optional, Any, List, Dict
import os
import secrets
from gerenciar_token import GerenciadorToken
import uvicorn
import urllib3
from enum import Enum

urllib3.disable_warnings()


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
NOME = os.getenv('NOME')
SENHA = os.getenv('SENHA')
PORT= os.getenv('PORT', 8000)


class AmbientesEnum(str, Enum):
    PROD = "prod"
    DEV = "dev"

# Configuração dos ambientes
AMBIENTES_CONFIG = {
    AmbientesEnum.PROD: {
        "url": os.getenv('URL_LOGIN_PROD', ''),
        "nome": os.getenv('NOME'),
        "senha": os.getenv('SENHA')
    },
    AmbientesEnum.DEV: {
        "url": os.getenv('URL_LOGIN_DEV', ''),
        "nome": os.getenv('NOME'),
        "senha": os.getenv('SENHA')
    }
}

# Cache para instâncias do GerenciadorToken
gerenciadores_cache: Dict[AmbientesEnum, GerenciadorToken] = {}

# Validações das variáveis de ambiente
assert NOME is not None, "NOME não está definido nas variáveis de ambiente"
assert SENHA is not None, "SENHA não está definido nas variáveis de ambiente"
assert AMBIENTES_CONFIG[AmbientesEnum.PROD]["url"] is not None, "URL_LOGIN_PROD não está definido nas variáveis de ambiente"
assert AMBIENTES_CONFIG[AmbientesEnum.DEV]["url"] is not None, "URL_LOGIN_DEV não está definido nas variáveis de ambiente"

# Configuração de autenticação Basic
security = HTTPBasic()

# Credenciais válidas
VALID_USERNAME = os.getenv('VALID_USERNAME')
VALID_PASSWORD = os.getenv('VALID_PASSWORD')

assert VALID_USERNAME is not None, "VALID_USERNAME não está definido nas variáveis de ambiente"
assert VALID_PASSWORD is not None, "VALID_PASSWORD não está definido nas variáveis de ambiente"


# Função para obter gerenciador baseado no ambiente
def obter_gerenciador(ambiente: AmbientesEnum) -> GerenciadorToken:
    """
    Obtém uma instância do GerenciadorToken para o ambiente especificado.
    Usa cache para evitar múltiplas inicializações.
    """
    if ambiente not in gerenciadores_cache:
        config = AMBIENTES_CONFIG[ambiente]
        gerenciadores_cache[ambiente] = GerenciadorToken(
            url_login=config["url"],
            nome=int(config["nome"]),
            senha=int(config["senha"])
        )

    return gerenciadores_cache[ambiente]

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

# Endpoint de saúde (COM autenticação)
@app.get("/health")
def health_check(username: str = Depends(verificar_autenticacao)):
    """Endpoint para verificar se a API está funcionando"""
    return {"status": "ok", "message": "API está funcionando"}

# Endpoint principal para executar SQL
@app.post("/sql/query", response_model=SQLResponse)
def executar_sql(
    ambiente: AmbientesEnum,
    query: SQLQuery,
    username: str = Depends(verificar_autenticacao)
):
    """
    Executa uma consulta SQL usando o GerenciadorToken no ambiente especificado.

    Requer autenticação via Basic Auth

    Parâmetros:
    - ambiente: "prod" ou "dev"
    - sql_query: Consulta SQL a ser executada

    Exemplo de requisição:
    ```json
    {
        "sql_query": "SELECT * FROM dual"
    }
    ```
    """
    try:
        # Obter gerenciador para o ambiente especificado
        gerenciador = obter_gerenciador(ambiente)

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
def status_token(
    ambiente: AmbientesEnum,
    username: str = Depends(verificar_autenticacao)
):
    """
    Retorna o status do token de autenticação do Consinco para o ambiente especificado.

    Requer autenticação via Basic Auth

    Parâmetros:
    - ambiente: "prod" ou "dev"
    """
    try:
        # Obter gerenciador para o ambiente especificado
        gerenciador = obter_gerenciador(ambiente)

        status = gerenciador.status_token()
        return {
            "success": True,
            "ambiente": ambiente.value,
            "status": status
        }
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Erro ao obter status do token: {str(e)}"
        )

# Endpoint raiz (COM autenticação)
@app.get("/")
def root(username: str = Depends(verificar_autenticacao)):
    """Redireciona para /docs"""
    return RedirectResponse(url="/docs")

# Executar servidor
if __name__ == "__main__":
    # Para desenvolvimento
    uvicorn.run(app, host="0.0.0.0", port=8001)
