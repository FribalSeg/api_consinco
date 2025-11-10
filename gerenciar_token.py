import requests
import json
import os
from datetime import datetime, timedelta
from typing import Optional, Dict
import re
import threading

class GerenciadorToken:
    """
    Classe para gerenciar tokens de autenticação automaticamente.
    Renova o token quando está vencido ou faltam menos de 10 minutos para expirar.
    """

    def __init__(self, url_login: str, nome: int, senha: int, nro_empresa: int = 1,
                 arquivo_cookies: str = None):
        """
        Inicializa o gerenciador de token.

        Args:
            url_login: URL do endpoint de login
            nome: Nome/ID do usuário
            senha: Senha do usuário
            nro_empresa: Número da empresa (padrão: 1)
            arquivo_cookies: Nome do arquivo para salvar cookies (padrão: 'cookies.json')
        """

        dominio = self.extrair_dominio(url_login)

        # Criar pasta tokens se não existir
        pasta_tokens = 'tokens'
        if not os.path.exists(pasta_tokens):
            os.makedirs(pasta_tokens)

        if arquivo_cookies is None:
            # remover tudo além do domínio para criar nome do arquivo
            url_login_limpo = re.sub(r'^https?://', '', dominio)  # remove protocolo
            url_login_limpo = re.sub(r':\d+', '', url_login_limpo)  # remove porta
            url_login_limpo = re.sub(r'/.*$', '', url_login_limpo)  # remove path
            arquivo_cookies = os.path.join(pasta_tokens, url_login_limpo + '_' + 'cookies.json')




        self.url_login = f"https://{dominio}/Login"
        self.cadastros_estruturais_url = f"https://{dominio}:8343/CadastrosEstruturaisAPI/api/v1/:entidade"
        self.api_sql_url = f"https://{dominio}:8343/ConstrutorAnaliseAPI/api/Analysis/GetSqlResult"
        self.cadastros_estruturais_ativar_categoria = f'https://{dominio}:8343/CadastrosEstruturaisAPI/api/v1/Familia/:codigo_categoria/ativar-categoria'
        self.informacoes_nutricionais_url = f"https://{dominio}:8343/CadastrosEstruturaisAPI/api/v1/Familia/informacao-nutricional"


        # self.url_login = url_login
        self.nome = nome
        self.senha = senha
        self.nro_empresa = nro_empresa
        self.arquivo_cookies = arquivo_cookies
        self.session = requests.Session()
        self._token_data: Optional[Dict] = None
        self._validade_token: Optional[datetime] = None
        self._lock = threading.Lock()  # Mutex para garantir thread-safety

    def consulta_sql(self, sql_text: str) -> Optional[Dict]:
        """
        Consulta SQL usando a API autenticada.

        Args:
            sql: Comando SQL a ser executado

        Returns:
            Dict: Resultado da consulta SQL se bem-sucedido, None caso contrário
        """
        session = self.obter_session_autenticada()

        body2 = """
        {
            "CommandText": "{SQL_TEXT}",
            "ConnectionType": 0,
            "Limit": null
        }
        """

        ss = requests.Session()

        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": f"Bearer {self.pegar_token_atualizado()['access_token']}"
        }

        dados_objetos = ss.post(self.api_sql_url, data=body2.replace("{SQL_TEXT}", sql_text), headers=headers, verify=False)

        if dados_objetos.status_code == 200:
            return dados_objetos.json()
        else:
            print(f'Erro na consulta SQL: {dados_objetos.status_code}')
            return None

    def extrair_dominio(self, url: str) -> str:
        # remover protocolo, porta e path do url
        url = re.sub(r'^https?://', '', url)  # remove protocolo
        url = re.sub(r':\d+', '', url)  # remove porta
        url = re.sub(r'/.*$', '', url)  # remove path

        return url


    def _fazer_login(self) -> bool:
        """
        Realiza o login e obtém um novo token.

        Returns:
            bool: True se o login foi bem-sucedido, False caso contrário
        """
        try:
            horario = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

            modelo_request = {
                'DataHoraLocal': horario,
                'returnUrl': '',
                'Nome': self.nome,
                'Senha': self.senha,
                'NroEmpresa': self.nro_empresa,
            }

            response = self.session.post(self.url_login, data=modelo_request, verify=False)

            if response.status_code == 200:
                # Salvar cookies
                cookies_dict = {cookie.name: cookie.value for cookie in self.session.cookies}
                with open(self.arquivo_cookies, 'w', encoding='utf-8') as f:
                    json.dump(cookies_dict, f, ensure_ascii=False, indent=4)

                # Extrair dados do token
                if 'oAuthToken' in cookies_dict:
                    self._token_data = json.loads(cookies_dict['oAuthToken'])
                    # Converter data de validade
                    self._validade_token = datetime.strptime(
                        self._token_data['.expires'],
                        '%Y-%m-%dT%H:%M:%SZ'
                    )

                    print(f'Login realizado com sucesso. Token válido até: {self._validade_token}')
                    return True
                else:
                    print('Token oAuthToken não encontrado nos cookies')
                    return False
            else:
                print(f'Falha no login. Status Code: {response.status_code}')
                print(f'Response: {response.text}')
                return False

        except Exception as e:
            print(f'Erro durante o login: {str(e)}')
            return False

    def _token_precisa_renovar(self) -> bool:
        """
        Verifica se o token precisa ser renovado.

        Returns:
            bool: True se o token precisa ser renovado, False caso contrário
        """
        if self._validade_token is None or self._token_data is None:
            return True

        # Verifica se faltam menos de 10 minutos para expirar
        agora = datetime.now()
        margem_seguranca = timedelta(minutes=10)

        return (self._validade_token - agora) <= margem_seguranca

    def _token_e_valido(self) -> bool:
        """
        Verifica se o token atual é válido (não expirou e não está próximo do vencimento).

        Returns:
            bool: True se o token é válido, False caso contrário
        """
        if self._validade_token is None or self._token_data is None:
            return False

        agora = datetime.now()
        margem_seguranca = timedelta(minutes=10)

        return (self._validade_token - agora) > margem_seguranca

    def carregar_token_salvo(self) -> bool:
        """
        Tenta carregar um token salvo do arquivo de cookies.

        Returns:
            bool: True se conseguiu carregar um token válido, False caso contrário
        """
        try:
            if not os.path.exists(self.arquivo_cookies):
                return False

            with open(self.arquivo_cookies, 'r', encoding='utf-8') as f:
                cookies_dict = json.load(f)

            if 'oAuthToken' not in cookies_dict:
                return False

            self._token_data = json.loads(cookies_dict['oAuthToken'])

            # fuso horario UTC
            self._validade_token = datetime.strptime(
                self._token_data['.expires'],
                '%Y-%m-%dT%H:%M:%SZ'
            )
            # compensar fuso horario local se necessário
            self._validade_token = self._validade_token + timedelta(hours=-3)

            # Recriar cookies na sessão
            for name, value in cookies_dict.items():
                self.session.cookies.set(name, value)

            if not self._token_precisa_renovar():
                print(f'Token carregado do arquivo. Válido até: {self._validade_token}')
                return True
            else:
                print('Token salvo está próximo do vencimento ou expirado')
                return False

        except Exception as e:
            print(f'Erro ao carregar token salvo: {str(e)}')
            return False

    def pegar_token_atualizado(self) -> Optional[Dict]:
        """
        Retorna um token válido, renovando-o se necessário.
        Thread-safe: múltiplas requisições simultâneas usarão o mesmo token.

        Returns:
            Dict: Dados do token se válido, None caso contrário
        """
        # Primeiro verifica se já tem um token válido sem lock (fast path)
        if self._token_e_valido():
            print(f'Token atual ainda é válido até: {self._validade_token}')
            return self._token_data

        # Se precisar renovar ou carregar, usa lock para garantir que apenas uma thread faça isso
        with self._lock:
            # Double-check: outra thread pode ter renovado enquanto esperávamos o lock
            if self._token_e_valido():
                print(f'Token foi renovado por outra requisição. Válido até: {self._validade_token}')
                return self._token_data

            # Primeiro tenta carregar token salvo se não há token em memória
            if self._token_data is None:
                self.carregar_token_salvo()

            # Verifica novamente se o token atual já é válido após carregar
            if self._token_e_valido():
                print(f'Token carregado é válido até: {self._validade_token}')
                return self._token_data

            # Se chegou aqui, o token precisa ser renovado
            if self._token_precisa_renovar():
                print('Token expirado ou próximo do vencimento. Renovando...')
                if not self._fazer_login():
                    return None

            return self._token_data

    def requisicao_get(self, url: str, params: Dict = None) -> Optional[requests.Response]:
        """
        Realiza uma requisição GET autenticada.

        Args:
            url: URL do endpoint
            params: Parâmetros da requisição

        Returns:
            requests.Response: Resposta da requisição se bem-sucedida, None caso contrário
        """
        session = self.obter_session_autenticada()
        if session is None:
            print('Sessão não autenticada. Não é possível fazer a requisição GET.')
            return None

        cabecalhos = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {self.pegar_token_atualizado()["access_token"]}'
        }

        response = session.get(url, params=params, verify=False, headers=cabecalhos)

        if response.status_code == 200:
            return response
        else:
            print(f'Erro na requisição GET: {response.status_code}')
            return None

    def requisicao_post(self, url: str, json: Dict = None, data: Dict = None) -> Optional[requests.Response]:
        """
        Realiza uma requisição POST autenticada.

        Args:
            url: URL do endpoint
            data: Dados da requisição

        Returns:
            requests.Response: Resposta da requisição se bem-sucedida, None caso contrário
        """
        cabecalhos = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {self.pegar_token_atualizado()["access_token"]}'
        }

        session = self.obter_session_autenticada()
        if session is None:
            print('Sessão não autenticada. Não é possível fazer a requisição POST.')
            return None

        response = session.post(url, json=json, data=data, verify=False, headers=cabecalhos)

        if response.status_code == 200:
            return response
        else:
            print(f'Erro na requisição POST: {response.status_code}')
            return None


    def obter_session_autenticada(self) -> Optional[requests.Session]:
        """
        Retorna uma sessão com cookies de autenticação válidos.

        Returns:
            requests.Session: Sessão autenticada se válida, None caso contrário
        """
        if self.pegar_token_atualizado() is not None:
            return self.session
        return None

    def tempo_restante_token(self) -> Optional[timedelta]:
        """
        Retorna o tempo restante até a expiração do token.

        Returns:
            timedelta: Tempo restante ou None se não há token válido
        """
        if self._validade_token is None:
            return None

        agora = datetime.now()
        tempo_restante = self._validade_token - agora

        return tempo_restante if tempo_restante.total_seconds() > 0 else timedelta(0)

    def status_token(self) -> Dict:
        """
        Retorna informações sobre o status atual do token.

        Returns:
            Dict: Informações do status do token
        """
        token_valido = self._token_data is not None and not self._token_precisa_renovar()
        tempo_restante = self.tempo_restante_token()

        return {
            'token_valido': token_valido,
            'validade': self._validade_token.isoformat() if self._validade_token else None,
            'tempo_restante': str(tempo_restante) if tempo_restante else None,
            'precisa_renovar': self._token_precisa_renovar()
        }

    def ativar_categoria(self, codigo_categoria: str) -> bool:
        """
        Ativa uma categoria específica usando a API.

        Args:
            codigo_categoria: Código da categoria a ser ativada

        Returns:
            bool: True se a categoria foi ativada com sucesso, False caso contrário
        """
        session = self.obter_session_autenticada()
        if session is None:
            print('Sessão não autenticada. Não é possível ativar a categoria.')
            return False

        url_ativar = self.cadastros_estruturais_ativar_categoria.replace(':codigo_categoria', codigo_categoria)

        response = session.post(url_ativar, verify=False)

        if response.status_code == 200:
            print(f'Categoria {codigo_categoria} ativada com sucesso.')
            return True
        else:
            print(f'Falha ao ativar categoria {codigo_categoria}. Status Code: {response.status_code}')
            return False

