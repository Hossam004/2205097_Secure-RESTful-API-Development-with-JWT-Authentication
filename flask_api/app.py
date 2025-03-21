from flask import Flask, request, jsonify
import jwt
import datetime
import pymysql
import bcrypt
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'

# الاتصال بقاعدة البيانات MySQL
def get_db_connection():
    return pymysql.connect(
        host="localhost",
        user="root",  # غيره لو كان عندك مستخدم مختلف
        password="",  # ضع الباسورد لو عندك
        database="flask_api",
        cursorclass=pymysql.cursors.DictCursor
    )

# إنشاء الجداول إذا لم تكن موجودة
def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            username VARCHAR(255) UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS products (
            pid INT AUTO_INCREMENT PRIMARY KEY,
            pname VARCHAR(255) NOT NULL,
            description TEXT,
            price DECIMAL(10,2) NOT NULL,
            stock INT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    conn.commit()
    conn.close()

# Middleware للتحقق من الـ JWT
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('x-access-token')
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = data['username']
        except:
            return jsonify({'message': 'Token is invalid!'}), 401
        return f(current_user, *args, **kwargs)
    return decorated

# تسجيل مستخدم جديد
@app.route('/signup', methods=['POST'])
def signup():
    data = request.json
    name = data['name']
    username = data['username']
    password = data['password'].encode('utf-8')

    hashed_password = bcrypt.hashpw(password, bcrypt.gensalt())

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO users (name, username, password) VALUES (%s, %s, %s)", 
                       (name, username, hashed_password.decode('utf-8')))
        conn.commit()
        return jsonify({'message': 'User registered successfully'})
    except pymysql.IntegrityError:
        return jsonify({'message': 'Username already exists'}), 400
    finally:
        conn.close()

# تسجيل الدخول وإرجاع JWT
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data['username']
    password = data['password'].encode('utf-8')

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username=%s", (username,))
    user = cursor.fetchone()
    conn.close()

    if user and bcrypt.checkpw(password, user['password'].encode('utf-8')):
        token = jwt.encode({'username': username, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=10)}, 
                           app.config['SECRET_KEY'], algorithm="HS256")
        return jsonify({'token': token})
    
    return jsonify({'message': 'Invalid username or password'}), 401

# إضافة منتج (محمية بـ JWT)
@app.route('/products', methods=['POST'])
@token_required
def add_product(current_user):
    data = request.json
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO products (pname, description, price, stock) VALUES (%s, %s, %s, %s)", 
                   (data['pname'], data.get('description', ''), data['price'], data['stock']))
    conn.commit()
    conn.close()
    return jsonify({'message': 'Product added successfully'})

# جلب جميع المنتجات (محمية بـ JWT)
@app.route('/products', methods=['GET'])
@token_required
def get_products(current_user):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM products")
    products = cursor.fetchall()
    conn.close()
    return jsonify({'products': products})

# جلب منتج معين (محمية بـ JWT)
@app.route('/products/<int:pid>', methods=['GET'])
@token_required
def get_product(current_user, pid):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM products WHERE pid=%s", (pid,))
    product = cursor.fetchone()
    conn.close()
    if product:
        return jsonify({'product': product})
    return jsonify({'message': 'Product not found'}), 404

# تعديل منتج معين (محمية بـ JWT)
@app.route('/products/<int:pid>', methods=['PUT'])
@token_required
def update_product(current_user, pid):
    data = request.json
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE products SET pname=%s, description=%s, price=%s, stock=%s WHERE pid=%s", 
                   (data['pname'], data.get('description', ''), data['price'], data['stock'], pid))
    conn.commit()
    conn.close()
    return jsonify({'message': 'Product updated successfully'})

# حذف منتج معين (محمية بـ JWT)
@app.route('/products/<int:pid>', methods=['DELETE'])
@token_required
def delete_product(current_user, pid):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM products WHERE pid=%s", (pid,))
    conn.commit()
    conn.close()
    return jsonify({'message': 'Product deleted successfully'})

# تحديث بيانات مستخدم
@app.route('/users/<int:id>', methods=['PUT'])
@token_required
def update_user(current_user, id):
    data = request.json
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET name=%s, username=%s WHERE id=%s", 
                   (data['name'], data['username'], id))
    conn.commit()
    conn.close()
    return jsonify({'message': 'User updated successfully'})

if __name__ == '__main__':
    init_db()
    app.run(debug=True)


