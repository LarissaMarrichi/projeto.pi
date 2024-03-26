from flask import Flask, render_template, request, redirect, url_for, flash
import sqlite3
import re
import os

app = Flask(__name__)
app.secret_key = 'sua_chave_secreta'

def validate_email(email):
    return bool(re.match(r'^[\w\.-]+@[\w\.-]+$', email))

def validate_password(password):
    return len(password) >= 8 and any(c.isupper() for c in password) and any(c.islower() for c in password) and any(c.isdigit() for c in password)

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Recupere os dados do formulário
        username = request.form['username']
        password = request.form['password']

        # Verifique se o arquivo do banco de dados existe
        db_path = os.path.join(app.root_path, 'data', 'clients.db')
        if not os.path.exists(db_path):
            flash('login não encontrado.', 'error')
            return render_template('login.html')

        # Verifique se o usuário está no banco de dados
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM clients WHERE name = ? AND password = ?", (username, password))
        user = cursor.fetchone()
        conn.close()

        if user:
            # Usuário autenticado com sucesso
            flash('Login bem-sucedido!', 'success')
            return redirect(url_for('dashboard'))
        else:
            # Credenciais inválidas
            flash('Nome de usuário ou senha incorretos.', 'error')
    
    # Renderize a página de login (GET request)
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    conn = None  # Inicializa conn como None
    if request.method == 'POST':
        username = request.form['username']
        address = request.form['address']
        phonenumber = request.form['phonenumber']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if not all([username, address, phonenumber, email, password, confirm_password]):
            flash('Todos os campos são obrigatórios.', 'error')
            return redirect(url_for('register', 
                                    username=username,
                                    address=address,
                                    phonenumber=phonenumber,
                                    email=email))
        
        if not validate_email(email):
            flash('Por favor, insira um endereço de e-mail válido.', 'error')
            return redirect(url_for('register', 
                                    username=username,
                                    address=address,
                                    phonenumber=phonenumber,
                                    email=email))

        if not validate_password(password):
            flash('A senha deve ter pelo menos 8 caracteres e conter pelo menos uma letra maiúscula, uma letra minúscula e um número.', 'error')
            return redirect(url_for('register', 
                                    username=username,
                                    address=address,
                                    phonenumber=phonenumber,
                                    email=email))

        if password != confirm_password:
            flash('As senhas não coincidem.', 'error')
            return redirect(url_for('register', 
                                    username=username,
                                    address=address,
                                    phonenumber=phonenumber,
                                    email=email))

        db_path = os.path.join(app.root_path, 'ella', 'data', 'clients.db')
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            cursor.execute("SELECT * FROM clients WHERE name = ?", (username,))
            existing_user = cursor.fetchone()
            if existing_user:
                flash('Nome de usuário já existe. Escolha outro.', 'error')
                return redirect(url_for('register', 
                                        username=username,
                                        address=address,
                                        phonenumber=phonenumber,
                                        email=email))
            
            cursor.execute("INSERT INTO clients (name, address, phonenumber, email, password) VALUES (?, ?, ?, ?, ?)", (username, address, phonenumber, email, password))
            conn.commit()
            flash('Cliente registrado com sucesso!', 'success')
            return redirect(url_for('login'))  # Redireciona para a página de login após o registro
        except sqlite3.IntegrityError as e:
            flash('Erro ao registrar cliente: {}'.format(e), 'error')
        finally:
            if conn is not None:  # Verifica se conn não é None antes de tentar fechar
                conn.close()  # Fecha a conexão se ela não for None

        return redirect(url_for('register'))

    return render_template('register.html')

if __name__ == '__main__':
    app.run(debug=True, port=5000)