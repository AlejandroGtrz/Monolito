
from flask import Flask, abort, request, jsonify, g, url_for, make_response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
import uuid
import os
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = 'the quick brown fox jumps over the lazy dog'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'

db=SQLAlchemy(app)

class User(db.Model):
    id=db.Column(db.Integer, primary_key=True)
    public_id=db.Column(db.String(50),unique=True)
    nombre=db.Column(db.String(50))
    email=db.Column(db.String(50))
    contrasena=db.Column(db.String(50))
class Cuestionario(db.Model):
    id=db.Column(db.Integer, primary_key=True)
    id_creador=db.Column(db.Integer)
    titulo=db.Column(db.String(100))
class CuestionarioUsuario(db.Model):
    id=db.Column(db.Integer, primary_key=True)
    id_usuario=db.Column(db.Integer)
    id_cuestionario=db.Column(db.Integer)
    terminado=db.Column(db.Boolean)
    puntuacion=db.Column(db.Float)
class Pregunta(db.Model):
    id=db.Column(db.Integer, primary_key=True)
    id_cuestionario=db.Column(db.Integer, db.ForeignKey('cuestionario.id'))
    texto=db.Column(db.String(100))
    tipo=db.Column(db.String(50))
class Opciones(db.Model):
    id=db.Column(db.Integer, primary_key=True)
    id_pregunta=db.Column(db.Integer, db.ForeignKey('pregunta.id'))
    texto_opcion=db.Column(db.String(100))
    valor=db.Column(db.Float)
class RespuestaUsuario(db.Model):
    id=db.Column(db.Integer, primary_key=True)
    id_cuestionario_usuario=db.Column(db.Integer, db.ForeignKey('cuestionario_usuario.id'))
    id_opcion=db.Column(db.Integer, db.ForeignKey('opciones.id'))
    id_pregunta=db.Column(db.Integer, db.ForeignKey('pregunta.id'))
    valor=db.Column(db.Float)
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        if not token:
            return jsonify({'message' : 'Token is missing'}), 401
        try:
            data=jwt.decode(token, app.config['SECRET_KEY'])
            current_user=User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message': 'Token is invalid'}), 401
        return f(current_user, *args, **kwargs)
    return decorated

@app.route('/cuestionarios', methods=['GET'])
def mostrar_cuestionarios():
    cuestionarios=Cuestionario.query
    list=[]
    for i in cuestionarios:
        list.append({'Titulo': i.titulo, 'Identificador': i.id})
    return jsonify(list)
@app.route('/register', methods=['POST'])
def crear_usuario():
    data = request.get_json()
    hashed_password= generate_password_hash(data['contrasena'], method='sha256')
    nombre=data['nombre']
    email=data['email']
    if User.query.filter_by(email = email).first() is not None:
        return jsonify({'mensaje': 'El usuario ya existe'})
    usuario_nuevo= User(public_id=str(uuid.uuid4()), nombre=nombre, email=email, contrasena=hashed_password)
    db.session.add(usuario_nuevo)
    db.session.commit()
    return jsonify({'mensaje': 'Usuario creado'})
@app.route('/cuestionario', methods=['POST'])
@token_required
def crear_cuestionario(current_user):
    data=request.get_json()
    titulo=data['titulo']
    cuestionario_nuevo=Cuestionario(id_creador=current_user.id,titulo=titulo)
    db.session.add(cuestionario_nuevo)
    db.session.flush()
    preguntas=data['preguntas']
    for p in preguntas:
        print(type(p))
        print(p)
        pregunta_nueva=Pregunta(id_cuestionario=cuestionario_nuevo.id, texto=p['pregunta'], tipo=p['tipo'])
        db.session.add(pregunta_nueva)
        db.session.flush()
        opciones=p['opciones']
        solucion=p['solucion']
        n=0
        for i in opciones:
            respuesta_nueva=Opciones(id_pregunta=pregunta_nueva.id, texto_opcion=i, valor=solucion[n])
            db.session.add(respuesta_nueva)
            n=n+1
    db.session.commit()
    return jsonify({'mensaje': 'Cuestionario creado'})
@app.route('/resolver/<cuestionario_id>', methods=['GET'])
@token_required
def iniciar_cuestionario(current_user, cuestionario_id):
    usuariocuestionario_nuevo=CuestionarioUsuario(id_usuario=current_user.id, id_cuestionario=cuestionario_id, puntuacion=0)
    db.session.add(usuariocuestionario_nuevo)
    db.session.flush()
    cuestionario=Cuestionario.query.filter(Cuestionario.id==cuestionario_id).first()
    x={'id_usuariocuestionario': usuariocuestionario_nuevo.id, 'titulo': cuestionario.titulo, 'preguntas': ''}
    preguntas=Pregunta.query.filter(Pregunta.id_cuestionario==cuestionario.id).all()
    list=[]
    for p in preguntas:
        opciones=Opciones.query.filter(Opciones.id_pregunta==p.id).all()
        l2=[]
        for o in opciones:
            l2.append({'id_opcion': o.id, 'opcion': o.texto_opcion })
        list.append({'id_pregunta': p.id, 'texto': p.texto, 'opciones': l2})
    x['preguntas']=list
    db.session.commit()
    return jsonify(x)
@app.route('/cuestionario/resultados', methods=['GET'])
@token_required
def obtener_resultados(current_user):
    usuario_cuestionarios=CuestionarioUsuario.query.filter_by(CuestionarioUsuario.id_usuario==current_user.id)
@app.route('/cuestionario/<id_cuestionario>', methods=['DELETE'])
@token_required
def borrar_cuestionario(current_user, id_cuestionario):
    cuestionario=Cuestionario.query.get_or_404(id_cuestionario)
    if(current_user.id==cuestionario.id_creador):
        db.session.delete(cuestionario)
    else:
        return jsonify({'Mensaje': 'Error, solo el usuario que ha creado el cuestionario puede eliminarlo'})
    db.session.commit()
    return jsonify({'Mensaje': 'El cuestionario ha sido borrado con exito'})
@app.route('/cuestionario/<id_cuestionario>', methods=['PUT'])
@token_required
def actualizar_cuestionario(current_user, id_cuestionario):
    cuestionario=Cuestionario.query.get_or_404(id_cuestionario)
    if(current_user.id!=cuestionario.id_creador):
        return jsonify({'Mensaje': 'Error, solo el usuario que ha creado el cuestionario puede eliminarlo'})
@app.route('/opcion', methods=['POST'])
@token_required
def responder_opcion(current_user):
    data=request.get_json()
    id_opcion=data['id_opcion']
    id_usuariocuestionario=data['id_usuariocuestionario']
    id_pregunta=data['id_pregunta']
    opcion=Opciones.query.get_or_404(id_opcion)
    usuariocuestionario=CuestionarioUsuario.query.get_or_404(id_usuariocuestionario)
    if RespuestaUsuario.query.filter(RespuestaUsuario.id_cuestionario_usuario==id_usuariocuestionario).filter(RespuestaUsuario.id_pregunta==id_pregunta).first() is not None:
        return jsonify({'Mensaje': 'Pregunta ya contestada'})
    nueva_respuesta=RespuestaUsuario(id_pregunta=id_pregunta,id_opcion=id_opcion,id_cuestionario_usuario=id_usuariocuestionario, valor=opcion.valor)
    usuariocuestionario.puntuacion=usuariocuestionario.puntuacion+opcion.valor
    msg=''
    if opcion.valor<=0:
        msg='Incorrecta'
    else:
        msg='Correcta'
    db.session.add(nueva_respuesta)
    db.session.commit()
    return jsonify({'Resultado': msg})
@app.route('/')
def inicio():
    return jsonify({'Mensaje':'Hola'})
@app.route('/login')
def login():
    auth= request.get_json()
    email=auth['email']
    contrasena=auth['contrasena']
    user= User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"message": "Usuario no encontrado"})
    if check_password_hash(user.contrasena, contrasena):
        token=jwt.encode({'public_id': user.public_id,'exp': datetime.datetime.utcnow()+datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'], algorithm='HS256')
        return jsonify({'token': token.decode('UTF-8')})
    return jsonify({'token': "Error"})
if __name__=='__main__':
    if not os.path.exists('db.sqlite'):
        db.create_all()
    port = int(os.environ.get("PORT", 5050))
    app.run(host='0.0.0.0', port=port)
