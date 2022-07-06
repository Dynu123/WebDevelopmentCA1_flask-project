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


app = Flask(__name__)
CORS(app=app)
app.logger.addHandler(logging.StreamHandler(sys.stdout))
app.logger.setLevel(logging.ERROR)
#app configurations

app.config['SECRET_KEY'] = 'thisisimportant'
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
    
    def __init__(self, public_id, name, email, phone, password):
        self.public_id = public_id
        self.name = name
        self.email = email
        self.phone = phone
        self.password = password
        
#Transaction table
class TransactionTable(db.Model):
    transaction_id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255))
    amount = db.Column(db.String(255))
    type = db.Column(db.String(255))
    date = db.Column(db.String(255))
    note = db.Column(db.String(255))
    user_id = db.Column(db.Integer) #db.ForeignKey('UserTable.id'))
    #user = db.relationship('UserTable', backref='transactions')
    
    def __init__(self, title, amount, type, date, note, user_id):
        self.title = title
        self.amount = amount
        self.type = type
        self.date = date
        self.note = note
        self.user_id = user_id 
    
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
    new_user = UserTable(str(uuid.uuid4()), 
                         input['name'], 
                         input['email'], 
                         input['phone'], 
                         hashed_password)
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
                                    'exp': datetime.datetime.utcnow()+datetime.timedelta(days=30)}, 
                                   app.config['SECRET_KEY'])
                
                return make_response({'result': {'data': {'name': get_user.name,
                                                          'email': get_user.email,
                                                          'phone': get_user.phone,
                                                          'token': token,
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
    
    
#Add transaction
@app.route('/transactions/add', methods=['POST'])
@token_required
def addNewTransaction(current_user):
    input = request.get_json()
    new_transaction = TransactionTable(input['title'], 
                                       input['amount'], 
                                       input['type'], 
                                       input['date'], 
                                       input['note'], 
                                       input['user_id'])
    db.session.add(new_transaction)
    
    try:
        db.session.commit()
        db.session.refresh(new_transaction)
        input["transaction_id"] = new_transaction.transaction_id
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
@token_required
def updateTransactionById(current_user):
    input = request.get_json()
    get_transaction = TransactionTable.query.filter_by(transaction_id=input['transaction_id']).first()
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
        
#Get transactions list
@app.route('/transactions')
@token_required
def getAllTransactions(current_user): 
    try:
        get_transactions = TransactionTable.query.all()
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
@token_required
def getTransactionById(current_user, tId): 
    try:
        get_transaction = TransactionTable.query.filter_by(transaction_id=tId).first()
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
@token_required
def deleteTransactionById(current_user, tId): 
    try:
        get_transaction = TransactionTable.query.filter_by(transaction_id=tId).first()
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
        
    

    
    
    
    
    
if __name__ == "__main__":
    app.run(debug=True)