from crypt import methods
from email import message
from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
import datetime
import jwt
from functools import wraps
from sqlalchemy.sql import func
from flask_cors import CORS, cross_origin

app = Flask(__name__)

#cors = CORS(app, resources={r"/api/*": {"origins": "*"}})
CORS(app, allow_headers=['Content-Type', 'Access-Control-Allow-Origin',
                         'Access-Control-Allow-Headers', 'Access-Control-Allow-Methods'])

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///product.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PROPAGATE_EXCEPTIONS'] = True
app.config['SECRET_KEY'] = 'topsecret'

db = SQLAlchemy(app)


class ProductModel(db.Model):
    __tablename__ = 'products'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80))
    description = db.Column(db.Text)
    quantity = db.Column(db.Integer)
    price = db.Column(db.Float)
    created = db.Column(db.DateTime(timezone=True),
                        server_default=func.now())
    updated = db.Column(
        db.DateTime, onupdate=datetime.datetime.now)
    user_id = db.Column(db.Integer, nullable=True)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(50))
    password = db.Column(db.String(80))
    admin = db.Column(db.Boolean)
# ------------------------------------------------------------


def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers',
                         'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE')
    return response
# --------------------------------------------------------------------


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message': 'Token is missing!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(
                public_id=data['public_id']).first()
        except:
            return jsonify({'message': 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated


# -------------------------------------------------------------------------


@app.route('/user', methods=['GET'])
@token_required
def get_all_users(current_user):

    if not current_user.admin:
        return jsonify({'message': 'Cannot perform that function!'})

    users = User.query.all()

    output = []

    for user in users:
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['name'] = user.name
        user_data['password'] = user.password
        user_data['admin'] = user.admin
        output.append(user_data)

    return jsonify({'users': output})


@app.route('/user', methods=['POST'])
def create_user():

    data = request.get_json()

    hashed_password = generate_password_hash(data['password'], method='sha256')

    new_user = User(public_id=str(uuid.uuid4()),
                    name=data['name'], password=hashed_password, admin=True)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'New user created!'})


@app.route('/login', methods=['POST'])
def login():
    auth = request.get_json()

    if auth['username'] and auth['password']:
        user = User.query.filter_by(name=auth['username']).first()

        if not user:
            return make_response('User not present', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})

    if check_password_hash(user.password, auth['password']):
        token = jwt.encode({'public_id': user.public_id, 'exp': datetime.datetime.utcnow(
        ) + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])

        return jsonify({'token': token.decode('UTF-8')})

    return make_response('Use valid password', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})


# ------------------------------------------------------------------------------


@app.route('/product', methods=['GET'])
def get_all_products():
    products = ProductModel.query.all()

    output = []

    for product in products:
        product_data = {}
        product_data['id'] = product.id
        product_data['name'] = product.name
        product_data['description'] = product.description
        product_data['quantity'] = product.quantity
        product_data['price'] = product.price
        product_data['created'] = product.created
        product_data['updated'] = product.updated
        product_data['user_id'] = product.user_id
        output.append(product_data)

    return jsonify({'products': output})


@app.route('/product/<product_id>', methods=['GET'])
@token_required
def get_one_product(current_user, product_id):
    product = ProductModel.query.filter_by(
        id=product_id).first()

    if not product:
        return jsonify({'message': "No product found"})

    product_data = {}
    product_data['name'] = product.name
    product_data['description'] = product.description
    product_data['quantity'] = product.quantity
    product_data['price'] = product.price
    product_data['created'] = product.created
    product_data['updated'] = product.updated

    return jsonify(product_data)


@app.route('/product', methods=['POST'])
# @token_required
def create_products():
    data = request.get_json()

    new_product = ProductModel(
        name=data['name'], description=data['description'], quantity=data['quantity'], price=data['price'])
    db.session.add(new_product)
    db.session.commit()

    return jsonify({'message': "product created!"})


@app.route('/product/<product_id>', methods=['PUT'])
@token_required
def promote_products(current_user, product_id):
    data = request.get_json()
    product = ProductModel.query.filter_by(
        id=product_id, user_id=current_user.id).first()

    product.name = data["name"]
    product.description = data["description"]
    product.quantity = data["quantity"]
    product.price = data["price"]

    db.session.commit()

    return jsonify({'message': "product updated!"})


@app.route('/product/<product_id>', methods=['DELETE'])
@token_required
def delete_products(current_user, product_id):
    product = ProductModel.query.filter_by(
        id=product_id, user_id=current_user.id).first()

    if not product:
        return jsonify({'message': 'No product found!'})

    db.session.delete(product)
    db.session.commit()

    return jsonify({'message': 'product item deleted!'})


if __name__ == '__main__':
    app.run(port=5000, debug=True)
