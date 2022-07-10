from flask import Flask, request, jsonify, make_response, json
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
from marshmallow_sqlalchemy import SQLAlchemyAutoSchema
import uuid
import pymysql
from werkzeug.security import check_password_hash, generate_password_hash
import jwt
import datetime
import requests #for calling external api
from functools import wraps # for token authentication
from flask_cors import CORS, cross_origin
import logging
import sys

from flask_jwt_extended import (create_access_token, create_refresh_token, get_jwt_identity, jwt_required, JWTManager,  current_user,)


app = Flask(__name__)
CORS(app=app)
app.logger.addHandler(logging.StreamHandler(sys.stdout))
app.logger.setLevel(logging.ERROR)
#app configurations
app.config['WTF_CSRF_ENABLED'] = True
app.config['SECRET_KEY'] = 'thisisimportant'

# Setup the Flask-JWT-Extended extension
app.config["JWT_SECRET_KEY"] = "webCA1anditshouldbetopsecretcodethatcannotbeguessed"  # Change this!
jwt = JWTManager(app)
#
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_DATABASE_URI'] = "mysql://b5b7e9d2945fc0:f06fdd58@us-cdbr-east-05.cleardb.net/heroku_744c5b8a948159b"
pymysql.install_as_MySQLdb()
db = SQLAlchemy(app) 
ma = Marshmallow(app)


#User table
class UserTable(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(255))
    email = db.Column(db.String(255), unique=True)
    phone = db.Column(db.String(255), unique=True)
    password=db.Column(db.String(255))
    # one-to-many collection
    
    transactions = db.relationship("TransactionTable", backref="user")

#Transaction table
class TransactionTable(db.Model):
    transaction_id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255))
    amount = db.Column(db.String(255))
    type = db.Column(db.String(255))
    date = db.Column(db.String(255))
    note = db.Column(db.String(255))
    user_id = db.Column(db.Integer, db.ForeignKey("user_table.id"))

class UserSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = UserTable

class TransactionSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = TransactionTable
        
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

#Welcome screen
@app.route('/')
def index():
    return "Welcome to FinManager API"

#user registation
@app.route('/signup', methods=['POST'])

def createUser():
    input = request.get_json()
    check_user = UserTable.query.filter_by(email=input['email']).first()
    if check_user:
        return make_response({'result': {'data': {},
                                         'message': 'User {} already exists! Please try log in.'.format(check_user.email),
                                         'code': '400'}
                          }, 
                         200)
    hashed_password = generate_password_hash(input['password'], method='sha256')
    new_user = UserTable(public_id=str(uuid.uuid4()), 
                         name=input['name'], 
                         email=input['email'], 
                         phone=input['phone'], 
                         password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    
    return make_response({'result': {'data': {'name': new_user.name,
                                              'email': new_user.email,
                                              'phone': new_user.phone},
                                     'message': 'User created successfully!',
                                     'code': '200'}
                          }, 
                         200)
    
@jwt.user_identity_loader
def user_identity_lookup(user):
    return user.id


@jwt.user_lookup_loader
def user_lookup_callback(_jwt_header, jwt_data):
    identity = jwt_data["sub"]
    return UserTable.query.filter_by(id=identity).one_or_none()


#user login
@app.route('/login', methods=['POST'])

def login():
    email = request.form.get('email')
    password = request.form.get('password')
    
    if email and password:
        get_user = UserTable.query.filter_by(email=email).one_or_none()
        if get_user:
            if check_password_hash(get_user.password, password):
                token = create_access_token(identity=get_user)
                refresh_token = create_refresh_token(identity=get_user, expires_delta=False)
                #token = jwt.encode({'public_id':get_user.public_id,
                                   # 'exp': datetime.datetime.utcnow()+datetime.timedelta(days=30)}, 
                                   #app.config['SECRET_KEY'])
                
                return make_response({'result': {'data': {'name': get_user.name,
                                                          'email': get_user.email,
                                                          'phone': get_user.phone,
                                                          #'token': token,
                                                          'token': token,
                                                          'refresh_token': refresh_token,
                                                          'id': get_user.id},
                                                 'message': 'User logged in successfully!',
                                                 'code': '200'}
                          }, 
                         200)
            return make_response({'result': {'data': {},
                                             'message': 'Username and password does not match!',
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
    
    
#user profile update
@app.route('/user/update', methods=['PUT'])

@jwt_required()
def updateProfile():
    input = request.get_json()
    
    get_user = UserTable.query.filter_by(id=input['id']).first()
    if get_user:
        get_user.name = input['name']
        get_user.phone = input['phone']
        
        try:
            db.session.commit()
            db.session.refresh(get_user)
            userSchema = UserSchema()
            result = userSchema.dump(get_user)
            return make_response({'result': {'data': input,
                                        'message': 'User details updated successfully!',
                                        'code': '200'}
                            }, 
                            200)
        except Exception as e:
            return make_response({'result': {'data': {},
                                        'message': e,
                                        'code': '400'}
                            }, 
                            400)
    else :
         return make_response({'result': {'data': {},
                                         'message': 'No user found',
                                         'code': '400'}
                               }, 
                              200)
        
    
#Add transaction
@app.route('/transactions/add', methods=['POST'])

@jwt_required()
def addNewTransaction():
    input = request.get_json()
    user = current_user.id
    new_transaction = TransactionTable(title=input['title'], 
                                       amount=input['amount'], 
                                       type=input['type'], 
                                       date=input['date'], 
                                       note=input['note'], 
                                       user_id= user)
    db.session.add(new_transaction)
    
    try:
        db.session.commit()
        db.session.refresh(new_transaction)
        input["transaction_id"] = new_transaction.transaction_id
        input['user_id'] = user
        return make_response({'result': {'data': input,
                                     'message': 'Transaction added successfully!',
                                     'code': '200'}
                          }, 
                         200)
    except Exception as e:
        return make_response({'result': {'data': {},
                                     'message': 'SQL exception',
                                     'code': '400'}
                          }, 
                         400)
        
#Update transaction
@app.route('/transactions/update', methods=['PUT'])

@jwt_required()
def updateTransactionById():
    input = request.get_json()
    get_transaction = TransactionTable.query.filter_by(transaction_id=input['transaction_id'], user_id=current_user.id).first()
    if get_transaction:
        get_transaction.title = input['title']
        get_transaction.amount = input['amount']
        get_transaction.type = input['type']
        get_transaction.date = input['date']
        get_transaction.note = input['note']
        try:
            db.session.commit()
            db.session.refresh(get_transaction)
            transactionSchema = TransactionSchema()
            result = transactionSchema.dump(get_transaction)
            return make_response({'result': {'data': result,
                                        'message': 'Transaction updated successfully!',
                                        'code': '200'}
                            }, 
                            200)
        except Exception as e:
            return make_response({'result': {'data': {},
                                        'message': 'SQL exception',
                                        'code': '400'}
                            }, 
                            400)
    else :
         return make_response({'result': {'data': {},
                                         'message': 'No transactions found',
                                         'code': '400'}
                               }, 
                              200)
        
#Get transactions list
@app.route('/transactions')

@jwt_required()
def getAllTransactions(): 
    try:
        get_transactions = TransactionTable.query.filter_by(user_id=current_user.id).all()
        #if get_transactions:
        transactionSchema = TransactionSchema(many=True)
        result = transactionSchema.dump(get_transactions)
        return make_response({'result': {'data': result,
                                        'message': 'success',
                                        'code': 200}
                                }, 
                             200)
    except Exception as e:
        return make_response({'error': {'error': e.__str__(),
                                        'error_message': 'failure',
                                        'error_code': "400"}
                              }, 
                             400)
        
#Get type transactions list
@app.route('/transactions/<type>')

@jwt_required()
def getTransactionByType(type): 
    try:
        get_transactions = TransactionTable.query.filter_by(user_id=current_user.id, type=type).all()
        #if get_transactions:
        transactionSchema = TransactionSchema(many=True)
        result = transactionSchema.dump(get_transactions)
        return make_response({'result': {'data': result,
                                        'message': 'success',
                                        'code': 200}
                                }, 
                             200)
    except Exception as e:
        return make_response({'error': {'error': e.__str__(),
                                        'error_message': 'failure',
                                        'error_code': "400"}
                              }, 
                             400)

#Get transaction by id
@app.route('/transactions/<tId>')
@jwt_required()
def getTransactionById(tId): 
    try:
        get_transaction = TransactionTable.query.filter_by(transaction_id=tId, user_id=current_user.id).first()
        transactionSchema = TransactionSchema()
        result = transactionSchema.dump(get_transaction)
        if get_transaction:
            return make_response({'result': {'data': [result],
                                        'message': 'success',
                                        'code': 200}
                                }, 
                             200)
        return make_response({'result': {'data': [],
                                        'message': 'No results found',
                                        'code': 200}
                                }, 
                             200)
    except Exception as e:
        return make_response({'error': {'error': e.__str__(),
                                        'error_message': 'failure',
                                        'error_code': "400"}
                              }, 
                             400)

#Delete transaction by id
@app.route('/transactions/delete/<tId>', methods=['DELETE'])

@jwt_required()
def deleteTransactionById(tId): 
    try:
        get_transaction = TransactionTable.query.filter_by(transaction_id=tId, user_id=current_user.id).first()
        transactionSchema = TransactionSchema()
        result = transactionSchema.dump(get_transaction)
        if get_transaction:
            db.session.delete(get_transaction)
            db.session.commit()
            return make_response({'result': {'data': '',
                                        'message': 'Transaction deleted successfully',
                                        'code': 200}
                                }, 
                             200)
        return make_response({'result': {'data': [],
                                        'message': 'No results found',
                                        'code': 200}
                                }, 
                             200)
    except Exception as e:
        return make_response({'error': {'error': e.__str__(),
                                        'error_message': 'failure',
                                        'error_code': "400"}
                              }, 
                             400)
        
#Get products list
@app.route('/products')
@token_required
def getAllProducts(current_user): 
    url = 'http://makeup-api.herokuapp.com/api/v1/products.json'
    try:
        result = requests.get(url)
        result.raise_for_status()
        json = result.json()
        return make_response({'result': {'data': json,
                                        'message': 'success',
                                        'code': result.status_code}
                                }, result.status_code)
    except Exception as e:
        return make_response({'error': {'error': e.__str__(),
                                        'error_message': 'failure',
                                        'error_code': result.status_code}}, result.status_code)
    
#Get product by Id
@app.route('/products/<product_id>')
@token_required
def getProductById(current_user, product_id):
    url = 'http://makeup-api.herokuapp.com/api/v1/products/{}.json'.format(product_id)
    try:
        result = requests.get(url)
        result.raise_for_status()
        json = result.json()
        return make_response({'result': {'data': json,
                                        'message': 'success',
                                        'code': result.status_code}
                                }, result.status_code)
    except Exception as e:
        return make_response({'error': {'error': e.__str__(),
                                        'error_message': 'failure',
                                        'error_code': result.status_code}}, result.status_code)
    
#Search product by category/value
@app.route('/products/<search_category>/<value>')

@token_required
def getProductByType(current_user, search_category, value):
    url = 'http://makeup-api.herokuapp.com/api/v1/products.json?{}={}'.format(search_category, value)
    try:
        result = requests.get(url)
        result.raise_for_status()
        json = result.json()
        return make_response({'result': {'data': json,
                                        'message': 'success',
                                        'code': result.status_code}
                                }, result.status_code)
    except Exception as e:
        return make_response({'error': {'error': e.__str__(),
                                        'error_message': 'failure',
                                        'error_code': result.status_code}}, result.status_code)
        
    

@app.route("/test", methods=["GET"])
@jwt_required()
def test():
    # Access the identity of the current user with get_jwt_identity
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200
    
    
    
if __name__ == "__main__":
    app.run(debug=True)