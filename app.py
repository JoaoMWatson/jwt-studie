import re
import uuid
from datetime import datetime, timedelta
from functools import wraps

import jwt
import pymongo
from flask import Flask, request
from werkzeug.security import check_password_hash, generate_password_hash

import config

app = Flask(__name__)
conn = pymongo.MongoClient(config.MONGO_CONNECT_STRING)
db = conn['teste']


@app.route('/test', methods=['GET'])
def test():
    return 'Autorizado'


@app.route('/notest', methods=['GET'])
def notest():
    return 'Não precisa de auth'


@app.route('/singup', methods=['POST'])
def singup():
    response = {'success': False, 'message': 'Invalid Parameter'}

    try:
        coll = db['jwt-test']
        data = request.form
        name, email = data.get('name'), data.get('email')
        password = data.get('password')
        print(name, email, password)

        if name == None or email == None or password == None:
            return response, 202
        if check_email(email) == False:
            response['message'] = 'Email inválido'
            return response, 202
        if check_password(password) == False:
            response['message'] = 'Senha invalidada'
            return response, 202

        user = coll.find_one({'email': email})
        if not user:
            coll.insert_one(
                {
                    'user_id': str(uuid.uuid4()),
                    'user_name': name,
                    'email': email,
                    'password': generate_password_hash(password),
                }
            )
            response['message'] = 'Usuario criado com sucesso.'
            response['success'] = True

            return response, 201

        else:
            response['message'] = 'Email já cadastrado'

            return response, 202

    except Exception as ex:
        print(str(ex))
        return {'deu': 'ruim', 'message': ex}, 502


@app.route('/login')
def login():
    response = {
        'success': False,
        'message': 'Invalid parameters',
        'token': ""
    }
    
    try:
        coll = db['jwt-test']
        auth = request.form
        
        if not auth or not auth.get('email') or not auth.get('password'):
            response['message'] = 'Informações invalidas'
            return response, 422
        
        user = coll.find_one({'email': auth['email']})
        
        if not user:
            response['message'] = 'Não autorizado'
            return response, 401
        
        if check_password_hash(auth['password'], auth['password']):
            token = jwt.encode({
                'user_id': user['user_id'],
                'exp': datetime.utcnow() + timedelta(hours=24)
            }, config.SECRET_KEY)
            response['message'] = "token generated"
            response['token'] = token.decode('utf8')
            response['success'] = True
            return response, 200
        response['message'] = 'Invalid emailid or password'
        return response, 403
    except Exception as ex:
        print(str(ex))
        return response, 422


def check_email(email):
    if re.search(config.EMAIL_REGEX, email):
        return True
    else:
        return False


def check_password(password):
    if (
        len(password) >= 6
        and len(password) <= 20
        and any(char.isdigit() for char in password)
        and any(char.isupper() for char in password)
        and any(char.islower() for char in password)
    ):
        return True
    else:
        return False


if __name__ == '__main__':
    app.run(hots='0.0.0.0', port=5000, debug=True)
