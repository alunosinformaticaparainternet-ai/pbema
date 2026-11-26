from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    jsonify,
    flash
)

import sqlite3
import hashlib
import os

from pathlib import Path
from functools import wraps


# =====================================================
# CONFIGURAÇÃO DO APLICATIVO
# =====================================================

app = Flask(
    __name__,
    template_folder="templates",
    static_folder="static"
)

app.secret_key = os.environ.get(
    "PBEMA_SECRET_KEY",
    "chave-temporaria-pbema-troque-em-producao"
)

PASTA_PROJETO = Path(__file__).resolve().parent
CAMINHO_BANCO = PASTA_PROJETO / "banco.db"


# =====================================================
# CONEXÃO COM O BANCO
# =====================================================

def conectar_banco():
    conexao = sqlite3.connect(CAMINHO_BANCO)
    conexao.row_factory = sqlite3.Row
    conexao.execute("PRAGMA foreign_keys = ON")
    return conexao


# =====================================================
# SEGURANÇA DAS SENHAS
# =====================================================

def gerar_hash_senha(senha):
    return hashlib.pbkdf2_hmac(
        "sha256",
        senha.encode("utf-8"),
        b"PBEMA_salt_2026",
        600000
    ).hex()


# =====================================================
# CRIAÇÃO DAS TABELAS
# =====================================================

def criar_banco():
    conexao = conectar_banco()

    conexao.executescript("""
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nome TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            senha TEXT NOT NULL,
            tipo TEXT NOT NULL DEFAULT 'responsavel',
            cpf TEXT DEFAULT '',
            data_nascimento TEXT DEFAULT '',
            telefone TEXT DEFAULT '',
            endereco TEXT DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS alunos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nome TEXT NOT NULL,
            email TEXT UNIQUE,
            turma TEXT DEFAULT '',
            data_nascimento TEXT DEFAULT '',
            matricula TEXT DEFAULT '',
            responsavel_id INTEGER,
            FOREIGN KEY (responsavel_id)
                REFERENCES usuarios(id)
                ON DELETE SET NULL
        );

        CREATE TABLE IF NOT EXISTS notas (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            aluno_id INTEGER NOT NULL,
            disciplina TEXT NOT NULL,
            nota REAL NOT NULL CHECK (nota >= 0 AND nota <= 10),
            FOREIGN KEY (aluno_id)
                REFERENCES alunos(id)
                ON DELETE CASCADE,
            UNIQUE (aluno_id, disciplina)
        );

        CREATE TABLE IF NOT EXISTS frequencia (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            aluno_id INTEGER NOT NULL UNIQUE,
            total_aulas INTEGER NOT NULL DEFAULT 0,
            presencas INTEGER NOT NULL DEFAULT 0,
            faltas INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY (aluno_id)
                REFERENCES alunos(id)
                ON DELETE CASCADE,
            CHECK (total_aulas >= 0),
            CHECK (presencas >= 0),
            CHECK (faltas >= 0),
            CHECK (presencas + faltas = total_aulas)
        );

        CREATE TABLE IF NOT EXISTS notificacoes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            usuario_id INTEGER,
            titulo TEXT NOT NULL,
            mensagem TEXT NOT NULL,
            data_criacao TEXT DEFAULT CURRENT_TIMESTAMP,
            lida INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY (usuario_id)
                REFERENCES usuarios(id)
                ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS logins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            usuario_id INTEGER,
            email TEXT,
            data_login TEXT DEFAULT CURRENT_TIMESTAMP,
            status TEXT NOT NULL,
            FOREIGN KEY (usuario_id)
                REFERENCES usuarios(id)
                ON DELETE SET NULL
        );
    """)

    conexao.commit()
    conexao.close()


# =====================================================
# FUNÇÕES AUXILIARES
# =====================================================

def usuario_logado():
    usuario_id = session.get("usuario_id")

    if not usuario_id:
        return None

    conexao = conectar_banco()

    usuario = conexao.execute("""
        SELECT id, nome, email, tipo, cpf,
               data_nascimento, telefone, endereco
        FROM usuarios
        WHERE id = ?
    """, (usuario_id,)).fetchone()

    conexao.close()

    return usuario


def obter_aluno():
    conexao = conectar_banco()

    aluno = conexao.execute("""
        SELECT *
        FROM alunos
        ORDER BY id
        LIMIT 1
    """).fetchone()

    conexao.close()

    return aluno


def login_obrigatorio(funcao):
    @wraps(funcao)
    def verificar_login(*args, **kwargs):
        if not session.get("usuario_id"):
            flash("Entre na sua conta para continuar.", "aviso")
            return redirect(url_for("pagina_login"))

        return funcao(*args, **kwargs)

    return verificar_login


def preparar_resposta(dados, status=200):
    return jsonify(dados), status


# =====================================================
# PÁGINA INICIAL
# =====================================================

@app.route("/")
def inicio():
    if session.get("usuario_id"):
        return redirect(url_for("pagina_inicio"))

    return redirect(url_for("pagina_login"))


# =====================================================
# CADASTRO
# =====================================================

@app.route("/cadastro", methods=["GET", "POST"])
def pagina_cadastro():
    if request.method == "GET":
        return render_template("cadastro.html")

    nome = request.form.get("nome", "").strip()
    email = request.form.get("email", "").strip().lower()
    senha = request.form.get("senha", "")

    if not nome or not email or not senha:
        flash("Preencha todos os campos.", "erro")
        return redirect(url_for("pagina_cadastro"))

    if len(senha) < 6:
        flash("A senha deve ter pelo menos 6 caracteres.", "erro")
        return redirect(url_for("pagina_cadastro"))

    conexao = conectar_banco()

    try:
        conexao.execute("""
            INSERT INTO usuarios (nome, email, senha)
            VALUES (?, ?, ?)
        """, (nome, email, gerar_hash_senha(senha)))

        conexao.commit()

        flash("Conta criada com sucesso! Faça seu login.", "sucesso")
        return redirect(url_for("pagina_login"))

    except sqlite3.IntegrityError:
        flash("Este e-mail já está cadastrado.", "erro")
        return redirect(url_for("pagina_cadastro"))

    finally:
        conexao.close()


# =====================================================
# LOGIN
# =====================================================

@app.route("/login", methods=["GET", "POST"])
def pagina_login():
    if request.method == "GET":
        return render_template("login.html")

    email = request.form.get("email", "").strip().lower()
    senha = request.form.get("senha", "")

    conexao = conectar_banco()

    usuario = conexao.execute("""
        SELECT *
        FROM usuarios
        WHERE email = ?
    """, (email,)).fetchone()

    senha_valida = (
        usuario is not None
        and usuario["senha"] == gerar_hash_senha(senha)
    )

    conexao.execute("""
        INSERT INTO logins (usuario_id, email, status)
        VALUES (?, ?, ?)
    """, (
        usuario["id"] if senha_valida else None,
        email,
        "Sucesso" if senha_valida else "Falha"
    ))

    conexao.commit()
    conexao.close()

    if not senha_valida:
        flash("E-mail ou senha incorretos.", "erro")
        return redirect(url_for("pagina_login"))

    session.clear()
    session["usuario_id"] = usuario["id"]
    session["usuario_nome"] = usuario["nome"]
    session["usuario_email"] = usuario["email"]
    session["usuario_tipo"] = usuario["tipo"]

    return redirect(url_for("pagina_inicio"))


# =====================================================
# SAIR
# =====================================================

@app.route("/sair")
def sair():
    session.clear()
    flash("Você saiu da sua conta.", "sucesso")
    return redirect(url_for("pagina_login"))


# =====================================================
# INÍCIO
# =====================================================

@app.route("/inicio")
@login_obrigatorio
def pagina_inicio():
    return render_template("inicio.html")


# =====================================================
# AJUDA
# =====================================================

@app.route("/ajuda")
@login_obrigatorio
def pagina_ajuda():
    return render_template("ajuda.html")


# =====================================================
# NOTAS
# =====================================================

@app.route("/notas-pagina")
@login_obrigatorio
def pagina_notas():
    aluno = obter_aluno()

    notas = []
    media = 0

    if aluno:
        conexao = conectar_banco()

        notas = conexao.execute("""
            SELECT disciplina, nota
            FROM notas
            WHERE aluno_id = ?
            ORDER BY disciplina
        """, (aluno["id"],)).fetchall()

        conexao.close()

        if notas:
            media = round(
                sum(nota["nota"] for nota in notas) / len(notas),
                2
            )

    return render_template(
        "notas.html",
        aluno=aluno,
        notas=notas,
        media=media
    )


# =====================================================
# FREQUÊNCIA
# =====================================================

@app.route("/frequencia-pagina")
@login_obrigatorio
def pagina_frequencia():
    aluno = obter_aluno()
    frequencia = None
    porcentagem = 0

    if aluno:
        conexao = conectar_banco()

        frequencia = conexao.execute("""
            SELECT total_aulas, presencas, faltas
            FROM frequencia
            WHERE aluno_id = ?
        """, (aluno["id"],)).fetchone()

        conexao.close()

        if frequencia and frequencia["total_aulas"] > 0:
            porcentagem = round(
                frequencia["presencas"]
                / frequencia["total_aulas"] * 100,
                2
            )

    return render_template(
        "frequencia.html",
        aluno=aluno,
        frequencia=frequencia,
        porcentagem=porcentagem
    )


# =====================================================
# DESEMPENHO
# =====================================================

@app.route("/desempenho")
@login_obrigatorio
def pagina_desempenho():
    aluno = obter_aluno()
    media = 0
    porcentagem = 0
    situacao = "Sem dados"

    if aluno:
        conexao = conectar_banco()

        notas = conexao.execute("""
            SELECT nota
            FROM notas
            WHERE aluno_id = ?
        """, (aluno["id"],)).fetchall()

        frequencia = conexao.execute("""
            SELECT total_aulas, presencas
            FROM frequencia
            WHERE aluno_id = ?
        """, (aluno["id"],)).fetchone()

        conexao.close()

        if notas:
            media = round(
                sum(nota["nota"] for nota in notas) / len(notas),
                2
            )

        if frequencia and frequencia["total_aulas"] > 0:
            porcentagem = round(
                frequencia["presencas"]
                / frequencia["total_aulas"] * 100,
                2
            )

        if notas:
            situacao = "Aprovado" if media >= 6 else "Em recuperação"

    return render_template(
        "desempenho.html",
        aluno=aluno,
        media=media,
        porcentagem=porcentagem,
        situacao=situacao
    )


# =====================================================
# INFORMAÇÕES DO ALUNO
# =====================================================

@app.route("/informacoes")
@login_obrigatorio
def pagina_informacoes():
    aluno = obter_aluno()
    return render_template("informacoes.html", aluno=aluno)


# =====================================================
# VISUALIZAR ALUNO
# =====================================================

@app.route("/visualizar-aluno")
@login_obrigatorio
def pagina_visualizar_aluno():
    aluno = obter_aluno()
    return render_template(
        "visualizar-aluno.html",
        aluno=aluno
    )


# =====================================================
# PERFIL
# =====================================================

@app.route("/perfil", methods=["GET", "POST"])
@login_obrigatorio
def pagina_perfil():
    usuario_id = session["usuario_id"]

    if request.method == "POST":
        nome = request.form.get("nome", "").strip()
        cpf = request.form.get("cpf", "").strip()
        nascimento = request.form.get("data_nascimento", "").strip()
        telefone = request.form.get("telefone", "").strip()
        endereco = request.form.get("endereco", "").strip()

        if not nome:
            flash("O nome não pode ficar vazio.", "erro")
            return redirect(url_for("pagina_perfil"))

        conexao = conectar_banco()

        conexao.execute("""
            UPDATE usuarios
            SET nome = ?,
                cpf = ?,
                data_nascimento = ?,
                telefone = ?,
                endereco = ?
            WHERE id = ?
        """, (
            nome,
            cpf,
            nascimento,
            telefone,
            endereco,
            usuario_id
        ))

        conexao.commit()
        conexao.close()

        session["usuario_nome"] = nome

        flash("Perfil atualizado com sucesso!", "sucesso")
        return redirect(url_for("pagina_perfil"))

    usuario = usuario_logado()

    return render_template(
        "perfil.html",
        usuario=usuario
    )


# =====================================================
# NOTIFICAÇÕES
# =====================================================

@app.route("/notificacoes")
@login_obrigatorio
def pagina_notificacoes():
    conexao = conectar_banco()

    notificacoes = conexao.execute("""
        SELECT id, titulo, mensagem, data_criacao, lida
        FROM notificacoes
        WHERE usuario_id = ?
        ORDER BY id DESC
    """, (session["usuario_id"],)).fetchall()

    conexao.close()

    return render_template(
        "notificacoes.html",
        notificacoes=notificacoes
    )


@app.route("/notificacoes/marcar-lida/<int:notificacao_id>", methods=["POST"])
@login_obrigatorio
def marcar_notificacao_lida(notificacao_id):
    conexao = conectar_banco()

    conexao.execute("""
        UPDATE notificacoes
        SET lida = 1
        WHERE id = ? AND usuario_id = ?
    """, (notificacao_id, session["usuario_id"]))

    conexao.commit()
    conexao.close()

    return redirect(url_for("pagina_notificacoes"))


# =====================================================
# RECUPERAÇÃO DE SENHA
# =====================================================

@app.route("/esqueci-senha", methods=["GET", "POST"])
def pagina_esqueci_senha():
    if request.method == "GET":
        return render_template("esqueci-senha.html")

    email = request.form.get("email", "").strip().lower()
    nova_senha = request.form.get("nova_senha", "")
    confirmar_senha = request.form.get("confirmar_senha", "")

    if not email or not nova_senha or not confirmar_senha:
        flash("Preencha todos os campos.", "erro")
        return redirect(url_for("pagina_esqueci_senha"))

    if nova_senha != confirmar_senha:
        flash("As senhas não são iguais.", "erro")
        return redirect(url_for("pagina_esqueci_senha"))

    if len(nova_senha) < 6:
        flash("A senha deve ter pelo menos 6 caracteres.", "erro")
        return redirect(url_for("pagina_esqueci_senha"))

    conexao = conectar_banco()

    usuario = conexao.execute("""
        SELECT id
        FROM usuarios
        WHERE email = ?
    """, (email,)).fetchone()

    if not usuario:
        conexao.close()
        flash("Não foi encontrada uma conta com esse e-mail.", "erro")
        return redirect(url_for("pagina_esqueci_senha"))

    conexao.execute("""
        UPDATE usuarios
        SET senha = ?
        WHERE id = ?
    """, (gerar_hash_senha(nova_senha), usuario["id"]))

    conexao.commit()
    conexao.close()

    flash("Senha alterada. Faça login com a nova senha.", "sucesso")
    return redirect(url_for("pagina_login"))


# =====================================================
# API: TESTAR BANCO
# =====================================================

@app.route("/testar-banco")
def testar_banco():
    conexao = conectar_banco()

    tabelas = conexao.execute("""
        SELECT name
        FROM sqlite_master
        WHERE type = 'table'
        ORDER BY name
    """).fetchall()

    conexao.close()

    return jsonify({
        "mensagem": "Banco de dados conectado com sucesso!",
        "arquivo": str(CAMINHO_BANCO),
        "tabelas": [tabela["name"] for tabela in tabelas]
    })


# =====================================================
# API: CADASTRAR ALUNO
# =====================================================

@app.route("/alunos/cadastrar", methods=["POST"])
def cadastrar_aluno():
    dados = request.get_json(silent=True)

    if dados is None:
        dados = request.form

    nome = dados.get("nome", "").strip()
    email = dados.get("email", "").strip() or None
    turma = dados.get("turma", "").strip()
    nascimento = dados.get("data_nascimento", "").strip()
    matricula = dados.get("matricula", "").strip()

    if not nome:
        return jsonify({
            "erro": "O nome do aluno é obrigatório."
        }), 400

    conexao = conectar_banco()

    try:
        cursor = conexao.execute("""
            INSERT INTO alunos
                (nome, email, turma, data_nascimento, matricula)
            VALUES (?, ?, ?, ?, ?)
        """, (nome, email, turma, nascimento, matricula))

        aluno_id = cursor.lastrowid

        conexao.execute("""
            INSERT INTO frequencia
                (aluno_id, total_aulas, presencas, faltas)
            VALUES (?, 0, 0, 0)
        """, (aluno_id,))

        conexao.commit()

        return jsonify({
            "mensagem": "Aluno cadastrado com sucesso!",
            "aluno_id": aluno_id
        }), 201

    except sqlite3.IntegrityError:
        conexao.rollback()
        return jsonify({
            "erro": "Este e-mail já está cadastrado ou os dados são inválidos."
        }), 400

    finally:
        conexao.close()


# =====================================================
# API: LISTAR ALUNOS
# =====================================================

@app.route("/alunos")
def listar_alunos():
    conexao = conectar_banco()

    alunos = conexao.execute("""
        SELECT id, nome, email, turma,
               data_nascimento, matricula
        FROM alunos
        ORDER BY nome
    """).fetchall()

    conexao.close()

    return jsonify([dict(aluno) for aluno in alunos])


# =====================================================
# API: SALVAR NOTA
# =====================================================

@app.route("/notas/salvar", methods=["POST"])
def salvar_nota():
    dados = request.get_json(silent=True)

    if dados is None:
        dados = request.form

    try:
        aluno_id = int(dados.get("aluno_id", 0))
        nota = float(dados.get("nota", -1))
    except (ValueError, TypeError):
        return jsonify({
            "erro": "Informe o ID do aluno e uma nota válida."
        }), 400

    disciplina = dados.get("disciplina", "").strip()

    if not disciplina:
        return jsonify({
            "erro": "Informe a disciplina."
        }), 400

    if not 0 <= nota <= 10:
        return jsonify({
            "erro": "A nota deve estar entre 0 e 10."
        }), 400

    conexao = conectar_banco()

    try:
        aluno = conexao.execute(
            "SELECT id FROM alunos WHERE id = ?",
            (aluno_id,)
        ).fetchone()

        if aluno is None:
            return jsonify({
                "erro": "Aluno não encontrado."
            }), 404

        conexao.execute("""
            INSERT INTO notas (aluno_id, disciplina, nota)
            VALUES (?, ?, ?)
            ON CONFLICT(aluno_id, disciplina)
            DO UPDATE SET nota = excluded.nota
        """, (aluno_id, disciplina, nota))

        conexao.commit()

        return jsonify({
            "mensagem": "Nota salva com sucesso!"
        })

    finally:
        conexao.close()


# =====================================================
# API: CONSULTAR NOTAS
# =====================================================

@app.route("/notas/<int:aluno_id>")
def consultar_notas(aluno_id):
    conexao = conectar_banco()

    notas = conexao.execute("""
        SELECT disciplina, nota
        FROM notas
        WHERE aluno_id = ?
        ORDER BY disciplina
    """, (aluno_id,)).fetchall()

    conexao.close()

    return jsonify([dict(nota) for nota in notas])


# =====================================================
# API: SALVAR FREQUÊNCIA
# =====================================================

@app.route("/frequencia/salvar", methods=["POST"])
def salvar_frequencia():
    dados = request.get_json(silent=True)

    if dados is None:
        dados = request.form

    try:
        aluno_id = int(dados.get("aluno_id", 0))
        total_aulas = int(dados.get("total_aulas", -1))
        presencas = int(dados.get("presencas", -1))
        faltas = int(dados.get("faltas", -1))
    except (ValueError, TypeError):
        return jsonify({
            "erro": "Informe números válidos para a frequência."
        }), 400

    if min(total_aulas, presencas, faltas) < 0:
        return jsonify({
            "erro": "Os valores não podem ser negativos."
        }), 400

    if presencas + faltas != total_aulas:
        return jsonify({
            "erro": "O total de aulas deve ser igual a presenças mais faltas."
        }), 400

    conexao = conectar_banco()

    try:
        aluno = conexao.execute(
            "SELECT id FROM alunos WHERE id = ?",
            (aluno_id,)
        ).fetchone()

        if aluno is None:
            return jsonify({
                "erro": "Aluno não encontrado."
            }), 404

        conexao.execute("""
            INSERT INTO frequencia
                (aluno_id, total_aulas, presencas, faltas)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(aluno_id)
            DO UPDATE SET
                total_aulas = excluded.total_aulas,
                presencas = excluded.presencas,
                faltas = excluded.faltas
        """, (aluno_id, total_aulas, presencas, faltas))

        conexao.commit()

        porcentagem = (
            round(presencas / total_aulas * 100, 2)
            if total_aulas > 0 else 0
        )

        return jsonify({
            "mensagem": "Frequência salva com sucesso!",
            "total_aulas": total_aulas,
            "presencas": presencas,
            "faltas": faltas,
            "porcentagem_presenca": porcentagem
        })

    finally:
        conexao.close()


# =====================================================
# API: CONSULTAR FREQUÊNCIA
# =====================================================

@app.route("/frequencia/<int:aluno_id>")
def consultar_frequencia(aluno_id):
    conexao = conectar_banco()

    frequencia = conexao.execute("""
        SELECT total_aulas, presencas, faltas
        FROM frequencia
        WHERE aluno_id = ?
    """, (aluno_id,)).fetchone()

    conexao.close()

    if frequencia is None:
        return jsonify({
            "erro": "Frequência não encontrada."
        }), 404

    dados = dict(frequencia)

    total_aulas = dados["total_aulas"]
    presencas = dados["presencas"]

    dados["porcentagem_presenca"] = (
        round(presencas / total_aulas * 100, 2)
        if total_aulas > 0 else 0
    )

    return jsonify(dados)


# =====================================================
# EXECUTAR A APLICAÇÃO
# =====================================================

if __name__ == "__main__":
    criar_banco()
    app.run(debug=True)