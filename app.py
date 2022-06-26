from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import uuid
import pymysql
from werkzeug.security import check_password_hash, generate_password_hash
import jwt
import datetime
import requests #for calling external api
from functools import wraps

app = Flask(__name__)

#app configurations
app.config['SECRET_KEY'] = 'thisisimportant'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_DATABASE_URI'] = "mysql://b5b7e9d2945fc0:f06fdd58@us-cdbr-east-05.cleardb.net/heroku_744c5b8a948159b"
pymysql.install_as_MySQLdb()
db = SQLAlchemy(app)


#User table
class UserTable(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(255))
    email = db.Column(db.String(255), unique=True)
    phone = db.Column(db.String(255), unique=True)
    password=db.Column(db.String(255))
    
    def __init__(self, public_id, name, email, phone, password):
        self.public_id = public_id
        self.name = name
        self.email = email
        self.phone = phone
        self.password = password
    
db.create_all()
    
    
#User Authorization    
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'Authorization' in request.headers:
            token = request.headers['Authorization']
        if not token:
            return jsonify({'message': 'Token is missing'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = UserTable.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message': 'Token is invalid'}), 401
        return f(current_user, *args, **kwargs)
    return decorated

#user registation
@app.route('/signup', methods=['POST'])
def createUser():
    input = request.get_json()
    check_user = UserTable.query.filter_by(email=input['email']).first()
    if check_user:
        return make_response({'result': {'data': {},
                                         'message': 'User already exists',
                                         'code': '400'}
                          }, 
                         200)
    hashed_password = generate_password_hash(input['password'], method='sha256')
    new_user = UserTable(str(uuid.uuid4()), input['name'], input['email'], input['phone'], hashed_password)
    db.session.add(new_user)
    db.session.commit()
    
    return make_response({'result': {'data': {'name': new_user.name,
                                              'email': new_user.email,
                                              'phone': new_user.phone},
                                     'message': 'User created successfully!',
                                     'code': '200'}
                          }, 
                         200)
    

#user login
@app.route('/login', methods=['POST'])
def login():
    email = request.form.get('email')
    password = request.form.get('password')
    
    if email and password:
        get_user = UserTable.query.filter_by(email=email).first()
        if get_user:
            if check_password_hash(get_user.password, password):
                token = jwt.encode({'public_id':get_user.public_id,
                                    'exp': datetime.datetime.utcnow()+datetime.timedelta(minutes=30)}, 
                                   app.config['SECRET_KEY'])
                return make_response({'result': {'data': {'name': get_user.name,
                                                          'email': get_user.email,
                                                          'phone': get_user.phone,
                                                          'token': token},
                                                 'message': 'User logged in successfully!',
                                                 'code': '200'}
                          }, 
                         200)
            return make_response({'result': {'data': {},
                                             'message': 'Incorrect password',
                                             'code': '400'}
                          }, 
                         200)
        return make_response({'result': {'data': {},
                                         'message': 'User does not exist',
                                         'code': '400'}
                          }, 
                         400)
    return make_response({'result': {'data': {},
                                     'message': 'Username or password cannot be empty',
                                     'code': '400'}
                          }, 
                         400)
        
#Get products list
@app.route('/products')
@token_required
def getAllProducts(current_user): 
    result = requests.get('http://makeup-api.herokuapp.com/api/v1/products.json')
    return make_response({'result': {'data': result.json(),
                                     'message': '',
                                     'code': '200'}
                          }, 
                         200)
    
#Get product by Id
@app.route('/products/<product_id>')
@token_required
def getProductById(current_user, product_id):
    url = 'http://makeup-api.herokuapp.com/api/v1/products/{}.json'.format(product_id)
    result = requests.get(url)
    return make_response({'result': {'data': result.json(),
                                     'message': '',
                                     'code': '200'}
                          }, 
                         200)
    
#Search product by category/value
@app.route('/products/<search_category>/<value>')
@token_required
def getProductByType(current_user, search_category, value):
    url = 'http://makeup-api.herokuapp.com/api/v1/products.json?{}={}'.format(search_category, value)
    result = requests.get(url)
    json = result.json()
    if result.ok:
        return make_response({'result': {'data': json,
                                        'message': 'success',
                                        'code': result.status_code}
                            }, result.status_code)
    
    return make_response({'result': {'data': json,
                                        'message': 'failed',
                                        'code': result.status_code}
                            }, result.status_code)
    
    

if __name__ == "__main__":
    app.run(debug=True)