# Importar las bibliotecas necesarias de Flask y otros módulos
from flask import Blueprint, render_template, request, flash, redirect, url_for
from .models import User  # Importar el modelo User para interactuar con la base de datos
from werkzeug.security import generate_password_hash, check_password_hash  # Para manejar el hashing de contraseñas
from . import db  # Importar la instancia de la base de datos desde el archivo __init__.py
from flask_login import login_user, login_required, logout_user, current_user  # Para manejar la autenticación de usuarios

# Crear un objeto Blueprint para el módulo de autenticación
auth = Blueprint('auth', __name__)

# Ruta para la página principal (INICIAL)
@auth.route('/main', methods=['GET'])
def main():
    # Renderiza la plantilla "main.html" y pasa el usuario actual
    return render_template("main.html", user=current_user)

# Ruta para iniciar sesión
@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':  # Si el método de la solicitud es POST
        # Obtener el correo electrónico y la contraseña del formulario
        email = request.form.get('email')
        password = request.form.get('password')

        # Buscar al usuario en la base de datos por su correo electrónico
        user = User.query.filter_by(email=email).first()
        if user:  # Si el usuario existe
            # Verificar si la contraseña ingresada coincide con la almacenada
            if check_password_hash(user.password, password):
                flash('Logged in successfully!', category='success')  # Mensaje de éxito
                login_user(user, remember=True)  # Iniciar sesión para el usuario
                #return render_template("dashboard.html",user=current_user)
                return redirect(url_for('views.home'))  # Redirigir a la página DASHBOARD
            else:
                flash('Contraseña Incorrecta, por favor intenta denuevo!.', category='error')  # Mensaje de error si la contraseña es incorrecta
        else:
            flash('Este correo no esta registrado', category='error')  # Mensaje de error si el correo no existe

    # Renderizar la plantilla "login.html" en caso de GET o si hay errores
    return render_template("login.html", user=current_user)

# Ruta para cerrar sesión
@auth.route('/logout')
@login_required  # Requiere que el usuario esté autenticado
def logout():
    logout_user()  # Cerrar sesión del usuario
    return redirect(url_for('auth.login'))  # Redirigir a la página de inicio de sesión

# Ruta para registrarse (sign-up)
@auth.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':  # Si el método de la solicitud es POST
        # Obtener el correo electrónico, nombre y contraseñas del formulario
        email = request.form.get('email')
        first_name = request.form.get('firstName')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        # Comprobar si el correo ya está registrado
        user = User.query.filter_by(email=email).first()
        if user:
            flash('Ya esta registrado este EMAIL.', category='error')  # Mensaje de error si el correo ya existe
        elif len(email) < 4:
            flash('El correo debe de tener más de 3 caracteres.', category='error')  # Validación del correo
        elif len(first_name) < 2:
            flash('EL primer nombre tiene que tener más de un caracter.', category='error')  # Validación del nombre
        elif password1 != password2:
            flash('Confirmación de contraseña incorrecta, no son iguales!', category='error')  # Validación de contraseñas
        elif len(password1) < 7:
            flash('La contraseña debe de tener minimo 7 caracteres.', category='error')  # Validación de longitud de contraseña
        else:
            # Crear un nuevo usuario y almacenar la contraseña de forma segura
            new_user = User(email=email, first_name=first_name, password=generate_password_hash(password1, method='pbkdf2:sha256'))
            db.session.add(new_user)  # Agregar el nuevo usuario a la sesión de la base de datos
            db.session.commit()  # Confirmar los cambios en la base de datos
            login_user(new_user, remember=True)  # Iniciar sesión para el nuevo usuario
            flash('Account created!', category='success')  # Mensaje de éxito
            return redirect(url_for('views.home'))  # Redirigir a la página principal

    # Renderizar la plantilla "sign_up.html" en caso de GET o si hay errores
    return render_template("sign_up.html", user=current_user)