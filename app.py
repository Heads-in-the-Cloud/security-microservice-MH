from flask import Flask, jsonify, request, make_response
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import UniqueConstraint
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash

import uuid
import jwt
import datetime

app = Flask(__name__)

app.config['SECRET_KEY'] = 'eae03e718bba0fd549c981c8e6aabe44' #TO-DO Create environment variable file
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:D8abaseCred%40ials@localhost:3306/utopia'

db = SQLAlchemy(app)

class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    role_id = db.Column(db.Integer, nullable=False)
    given_name = db.Column(db.String, nullable=False)
    family_name = db.Column(db.String, nullable=False)
    username = db.Column(db.String, nullable=False, unique=True)
    password = db.Column(db.String, nullable=False)
    email = db.Column(db.String, nullable=False)
    phone = db.Column(db.String)


class Role(db.Model):
    __tablename__ = 'user_role'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None #to be replaced

        if'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        if not token:
            return jsonify({'message' : 'Token is missing'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(id=data['id']).first()
        except:
            return jsonify({'message' : 'Token is invalid'}), 401

        return f(current_user, *args, **kwargs)
    return decorated

@app.route('/login')
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Unable to verify user', 401, {'WWW-Authenticate': 'Basic realm="Login required"'})

    user = User.query.filter_by(username = auth.username).first()

    if not user:
        return make_response('Unable to verify user', 401, {'WWW-Authenticate': 'Basic realm="Login required"'})

    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'id': user.id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes = 30)}, app.config['SECRET_KEY'], algorithm = "HS256")

        return jsonify({'token': token.decode('UTF-8')})

    return make_response('Unable to verify user', 401, {'WWW-Authenticate': 'Basic realm="Login required"'})


@app.route('/signup', methods = ['POST'])
def signup():
    data = request.get_json()
    hashed_password = generate_password_hash(data['password'], method='sha256')

    user = User(role_id=data['role_id'], given_name=data['given_name'], family_name=data['family_name'], username=data['username'], password=hashed_password, email=data['email'], phone=data['phone'])
    db.session.add(user)
    db.session.commit()
    return jsonify({'message' : 'New user created'})

@app.route('/test', methods = ['GET'])
@token_required
def test(current_user):
    if not current_user.role_id == 1:
        return jsonify({'message': 'Not an admin'})

    return jsonify({'message': 'Admin'})

if __name__ == '__main__':
    app.run(debug = True)
