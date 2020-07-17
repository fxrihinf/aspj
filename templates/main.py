from flask import Flask, render_template, request, redirect, url_for, session, g, jsonify, abort, \
    render_template_string, flash, make_response
import urllib, urllib.parse
import warnings
from datetime import date
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Column, Integer, String, Float, TEXT, DECIMAL, text, DATE, Boolean
from ftplib import FTP
import os
import os.path
import random

with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    from flask_marshmallow import Marshmallow
from flask_jwt_extended import JWTManager, jwt_required, create_access_token
from flask_mail import Mail, Message
from Forms import RegistrationForm, LoginForm
from flask_autoindex import AutoIndex
from flask import json
from werkzeug.exceptions import HTTPException

app = Flask(__name__)
from werkzeug.security import generate_password_hash, check_password_hash

basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'toiletshop.db')
# app.config['JWT_SECRET_KEY'] = 'super-secret' #change
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# PREVENTION
# app.config['MAIL_SERVER']='smtp.mailtrap.io'
# app.config['MAIL_PORT'] = 2525
# app.config['MAIL_USERNAME'] = '16427074913315'
# app.config['MAIL_PASSWORD'] = '11a95aaee3a6f5'
# app.config['MAIL_USE_TLS'] = True
# app.config['MAIL_USE_SSL'] = False
# app.config['PERMANENT_SESSION_LIFETIME'] =  timedelta(minutes=5)
import re

# SESSION_COOKIE_SECURE = True use for https
# app.config['SESSION_COOKIE_SECURE']=True, cant log in if thru http
# app.config['SESSION_COOKIE_HTTPONLY']=True,
# app.config['SESSION_COOKIE_SAMESITE']='Lax'
# #
db = SQLAlchemy(app)
ma = Marshmallow(app)
jwt = JWTManager(app)
mail = Mail(app)
app.secret_key = os.urandom(24)


def db_create():
    db.create_all()
    print("Database created. 2")


def db_drop():
    db.drop_all()
    print("Database dropped. 2")


class UserSchema(ma.Schema):
    class Meta:
        fields = ('id', 'first_name', 'last_name', 'email', 'password', "is_authenticated")


#
class ItemsSchema(ma.Schema):
    class Meta:
        fields = ('item_id', 'item_image', 'item_name', 'item_desc', 'item_price', 'item_stock')


class UserCartSchema(ma.Schema):
    class Meta:
        fields = ('item_id', 'item_image', 'item_name', 'item_desc', 'item_price', 'item_stock', 'user_id')


class UserPaymentSchema(ma.Schema):
    class Meta:
        fields = ('user_id', 'name', 'email', 'address', 'city', 'state',
                  'zip', 'creditName', 'cardNum', 'expireMonth',
                  'expireYear', 'cvv')


class UserOrderSchema(ma.Schema):
    class Meta:
        fields = (
            'user_id', 'order_item_id', 'item_image', 'item_name', 'item_desc', 'item_price', 'item_quantity', 'date')


user_schema = UserSchema()
users_schema = UserSchema(many=True)

item_schema = ItemsSchema()
items_schema = ItemsSchema(many=True)

cart_schema1 = UserCartSchema()
cart_schema = UserCartSchema(many=True)

payments_schema = UserPaymentSchema(many=True)
orders_schema = UserOrderSchema(many=True)


# Database models
class User(db.Model):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    first_name = Column(String)
    last_name = Column(String)
    email = Column(String, unique=True)
    password = Column(String)
    is_authenticated = Column(Boolean)


class Reviews(db.Model):
    __tablename__ = "reviews"
    id = Column(Integer, primary_key=True)
    item_id = Column(Integer)
    username = Column(String)
    content = Column(TEXT)


class Items(db.Model):
    __tablename__ = "items"
    item_id = Column(Integer, primary_key=True)
    item_image = Column(String)
    item_name = Column(String)
    item_desc = Column(TEXT)
    item_price = Column(DECIMAL(6, 2))
    item_stock = Column(Integer)


class UserCart(db.Model):
    user_id = text('A163216549')
    __tablename__ = user_id  # get login user id
    item_id = Column(Integer, primary_key=True)
    item_image = Column(String)
    item_name = Column(String)
    item_desc = Column(TEXT)
    item_price = Column(DECIMAL(6, 2))
    item_stock = Column(Integer)


class UserPayment(db.Model):
    __tablename__ = "PaymentInfo"  # get login user id
    user_id = Column(String, primary_key=True)
    name = Column(String)
    email = Column(String)
    address = Column(String)
    city = Column(String)
    state = Column(String)
    zip = Column(Integer)
    creditName = Column(String)
    cardNum = Column(Integer)  # 4539579803742677850
    expireMonth = Column(String)
    expireYear = Column(Integer)
    cvv = Column(Integer)


class UserOrder(db.Model):
    __tablename__ = "Order"  # get login user id
    user_id = Column(Integer)
    order_item_id = Column(Integer, primary_key=True)
    item_image = Column(String)
    item_name = Column(String)
    item_desc = Column(TEXT)
    item_price = Column(DECIMAL(6, 2))
    item_quantity = Column(Integer)
    date = Column(String)


def db_seed():
    toiletpaper = Items(item_image='toiletpaper',
                        item_name='Toilet Paper',
                        item_desc='A thin sanitary absorbent paper usually in a roll for use in drying or cleaning oneself after defecation and urination. Soft 3ply toilet paper, feels nice against your anus',
                        item_price=7.00,
                        item_stock=150)

    toothpaste = Items(item_image='toothpaste',
                       item_name='Toothpaste',
                       item_desc='A paste dentifrice used with a toothbrush to clean and maintain the aesthetics and health of teeth, Mint flavored keeping your breath fresh',
                       item_price=5.50,
                       item_stock=200)

    toothbrush = Items(item_image='toothbrush',
                       item_name='Toothbrush',
                       item_desc='An oral hygiene instrument used to clean the teeth, gums, and tongue. Utilized with toothpaste',
                       item_price=2.50,
                       item_stock=200)

    shampoo = Items(item_image='shampoo',
                    item_name='Shampoo',
                    item_desc='Shampoo is a hair care product, in the form of a viscous liquid, that is used for cleaning hair during showers',
                    item_price=12.00,
                    item_stock=300)

    razor = Items(item_image='razor',
                  item_name='Manual razor',
                  item_desc='A razor is used to remove small hairs such as beards, leg hair, pubic hair, etc.',
                  item_price=20.00,
                  item_stock=100)

    db.session.add(toiletpaper)
    db.session.add(toothpaste)
    db.session.add(toothbrush)
    db.session.add(shampoo)
    db.session.add(razor)

    review1 = Reviews(item_id=2,
                      username="Testuser1",
                      content='This product is amazing! Cheap and good')

    review2 = Reviews(item_id=2,
                      username="Testuser2",
                      content='This product is bad! not worth!')

    review3 = Reviews(item_id=4,
                      username="Testuser3",
                      content='Great item! very nice i like it')

    db.session.add(review1)
    db.session.add(review2)
    db.session.add(review3)
    # password = 'P@ssw0rd'
    admin = User(first_name='Null',
                 last_name='Null',
                 email='admin@toilet.org',
                 password='password',
                 is_authenticated=True)
    # password=generate_password_hash(password,method='sha256'))

    db.session.add(admin)
    db.session.commit()
    print('Database seeded. 2')


db_drop()
db_create()
db_seed()

files_index = AutoIndex(app, browse_root=os.path.curdir, add_url_rules=False)


# Custom indexing
@app.route('/dir')
@app.route('/dir/<path:path>')
def autoindex(path='.'):
    return files_index.render_autoindex(path)


@app.errorhandler(404)
def page_not_found(error):
    print(basedir)
    template = '''
    <h1>That page doesn't exist.</h1>
    <h3>%s Not found</h3>''' % (urllib.parse.unquote(request.url))
    # print(request.url)
    # template = '''<h2>Hello {}!</h2>'''.format(urllib.parse.unquote(request.url))
    return render_template_string(template, dir=dir, help=help, locals=locals, ), 404


@app.route("/", methods=['GET', 'POST'])
def store():
    if g.user:
        if 'user' in session:
            if request.method == 'POST':
                content = request.form['comment']
                item_id = request.form.get("item_idd", "")
                statement = text(
                    'INSERT INTO reviews ("item_id","username","content") VALUES ("' + item_id + '","Moh Ze Le","' + content + '")')
                db.engine.execute(statement)
                return redirect('/')
            search_query = None
            search_query = request.args.get('q')

            items_list = []
            get_all_items = text('SELECT * FROM items')
            result = db.engine.execute(get_all_items).fetchall()
            print(result)
            for (row) in result:
                print("hellooo")
                print(row[2])
                print(search_query)
                print("end hellooo")
                if search_query is None or search_query.upper() in row[2].upper():
                    items_list.append(row)

            print(items_list)
            review_list = []
            get_all_reviews = text('SELECT * FROM reviews')
            result2 = db.engine.execute(get_all_reviews).fetchall()
            for (rev) in result2:
                review_list.append(rev)
            print(review_list)
            return render_template('store.html', items_list=items_list,
                                   search_query=search_query, review_list=review_list, name=session['user'])
    if request.method == 'POST':
        content = request.form['comment']
        item_id = request.form.get("item_idd", "")
        statement = text(
            'INSERT INTO reviews ("item_id","username","content") VALUES ("' + item_id + '","Moh Ze Le","' + content + '")')
        db.engine.execute(statement)
        return redirect('/')
    search_query = None
    search_query = request.args.get('q')

    items_list = []
    get_all_items = text('SELECT * FROM items')
    result = db.engine.execute(get_all_items).fetchall()
    print(result)
    for (row) in result:
        print("hellooo")
        print(row[2])
        print(search_query)
        print("end hellooo")
        if search_query is None or search_query.upper() in row[2].upper():
            items_list.append(row)

    print(items_list)
    review_list = []
    get_all_reviews = text('SELECT * FROM reviews')
    result2 = db.engine.execute(get_all_reviews).fetchall()
    for (rev) in result2:
        review_list.append(rev)
    print(review_list)

    # return 'hi' + session['user']

    return render_template('store.html', items_list=items_list,
                           search_query=search_query, review_list=review_list)


@app.route('/addItem/<int:item_id>', methods=['GET', 'POST'])
def addItem(item_id: int):
    db_create()
    user_id = text('A163216549')
    item = UserCart.query.filter_by(item_id=item_id).first()
    if item:
        return jsonify("There is an item in your cart already"), 409
    else:
        get_all_items = text('SELECT * FROM items')
        result = db.engine.execute(get_all_items).fetchall()
        for i in result:
            if i[0] == item_id:
                item_id = i[0]
                item_image = i[1]
                item_name = i[2]
                item_desc = i[3]
                item_price = i[4]
                item_stock = 1
                usercart = UserCart(item_id=item_id, item_image=item_image, item_name=item_name,
                                    item_desc=item_desc,
                                    item_price=item_price, item_stock=item_stock)
                db_create()
                db.session.add(usercart)
                db.session.commit()
                return redirect('/')
            else:
                pass


@app.route('/deleteItem/<int:item_id>', methods=['DELETE', 'POST'])
def deleteItem(item_id: int):
    item = UserCart.query.filter_by(item_id=item_id).first()
    if item:
        print(item)
        db.session.delete(item)
        db.session.commit()
        return render_template('cart.html')
    else:
        return jsonify(message="That item does not exist"), 404


#
@app.route('/cart')
def cart():
    cart_list = []
    user_id = 'A163216549'
    a = ('SELECT * FROM ' + user_id)
    print(a)
    get_all_items = text(a)
    result = db.engine.execute(get_all_items).fetchall()
    for item in result:
        print(item)
        cart_list.append(item)
        # print(item['item_id'])
    # print(cart_list)

    total = 0
    for item in cart_list:
        total += item['item_price']
    return render_template('cart.html', cart_list=cart_list, total=total)


@app.route('/checkOut', methods=["GET", "POST"])
def checkOut():
    user_id = 'A163216549'
    checkOutCart = []
    a = ('SELECT * FROM ' + user_id)
    get_all_items = text(a)
    result = db.engine.execute(get_all_items).fetchall()
    for item in result:
        print(item)
        checkOutCart.append(item)

    total = 0
    for item in checkOutCart:
        total += item['item_price']

    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        address = request.form['address']
        city = request.form['city']
        state = request.form['state']
        zip = request.form['zip']
        creditName = request.form['cardname']
        cardNum = request.form['cardnumber']  # 4539579803742677850
        expireMonth = request.form['expmonth']
        expireYear = request.form['expyear']
        cvv = request.form['cvv']
        all = UserPayment.query.all()
        all_payment = payments_schema.dump(all)
        exist = False
        for a in all_payment:
            if a['user_id'] == user_id:
                exist = True
        if exist:
            pass
        else:
            paymentInfo = UserPayment(user_id=user_id, name=name, email=email, address=address, city=city,
                                      state=state,
                                      zip=zip, creditName=creditName, cardNum=cardNum, expireMonth=expireMonth,
                                      expireYear=expireYear, cvv=cvv)
            db.session.add(paymentInfo)
            db.session.commit()

        for item in result:
            print(item)
            if item:
                today = date.today()
                order = UserOrder(user_id=user_id, order_item_id=random.randint(99999999999999, 999999999999999),
                                  item_image=item['item_image'], item_name=item['item_name'],
                                  item_desc=item['item_desc'], item_price=item['item_price'],
                                  item_quantity=item['item_stock'], date=today)
                db_create()
                db.session.add(order)
                db.session.commit()
        print(name, email, address, city, state, zip, creditName, cardNum, expireMonth, expireYear, cvv)
        items = UserCart.query.all()
        for i in items:
            db.session.delete(i)
        db.session.commit()
        return redirect('/')

    return render_template('checkOut.html', user_id=user_id, checkOutCart=checkOutCart, total=total)


@app.route('/orders')
def orders():
    user_id = 'A163216549'
    orderCart = []
    allOrder = UserOrder.query.all()
    result = orders_schema.dump(allOrder)
    for item in result:
        if item['user_id'] == user_id:
            orderCart.append(item)

    return render_template('orders.html', orderCart=orderCart)


@app.route('/info')
def info():
    return render_template('info.html')


@app.before_request
def before_request():
    g.user = None
    g.role = False
    if 'user' in session:
        g.user = session['user']
        if 'is_authenticated' in session:
            g.role = session['is_authenticated']


@app.route("/logout")
def logout():
    session.pop('user', None)
    print("User logged out.")
    # return render_template('store.html')
    return redirect('/')


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm(request.form)
    if request.method == 'POST' and form.validate():
        email = request.form['email']
        test = User.query.filter_by(email=email).first()
        if test:
            # return jsonify(message="Email exists"), 409
            msg = 'Error: Email taken!'
            print("*Email already exist.")  # cannot mention if exist or not, make everything default
            # flash("Email already exist!")
            password = request.form['password']
            confirm = request.form['confirm']
            if password != confirm:
                msg = 'Error: Password must match!'
                print("User not added")
                return render_template('register.html', form=form, msg=msg)
            print("User not added")
            return render_template('register.html', form=form, msg=msg)

        else:
            first_name = request.form['first_name']
            last_name = request.form['last_name']
            password = request.form['password']
            # print("Password:",password) ##prevention
            # if len(password) < 8:
            #     msg = 'Error: Password is too short!'
            #     return render_template('register.html', form=form, msg=msg)
            #
            # elif not any(char.isdigit() for char in password):
            #     msg = 'Error: Password must contain a digit!'
            #     return render_template('register.html', form=form, msg=msg)
            #
            # elif not any(char.isupper() for char in password):
            #     msg = 'Error: Password must contain uppercase!'
            #     return render_template('register.html', form=form, msg=msg)
            #
            # elif not re.search("[$#@]",password):
            #     msg = "Error: Password must contain unique characters!"
            #     return render_template('register.html', form=form, msg=msg)
            # # strength = password_check(password)
            # # print(strength)
            session['user'] = request.form['email']
            print("Test session:", session['user'])
            if g.role:
                user = User(first_name=first_name,
                            last_name=last_name,
                            email=email,
                            # password=generate_password_hash(password,method='sha256'))
                            password=password, is_authenticated=True)
            else:
                user = User(first_name=first_name,
                            last_name=last_name,
                            email=email,
                            # password=generate_password_hash(password,method='sha256'))
                            password=password, is_authenticated=False)
            db.session.add(user)
            db.session.commit()
            #
            # # return jsonify(message='User created yay'), 201
            print("User created")
            return redirect(url_for('login'))
    return render_template('register.html', form=form)


@app.route('/admin_info', methods=['GET'])
def admin_info():
    if g.user:
        if 'user' in session:
            # if session['user'] == 'admin@toilet.org':
            print("ADMIN PAGE")
            user_list = User.query.all()
            result = users_schema.dump(user_list)
            return jsonify(result)
            ##insert admin page here
            # follow this format for all admin def
    else:
        abort(403)
        # for admin access only


@app.route('/admin')
def admin():
    if g.user:
        if g.role:
            return render_template('admin.html')
        return render_template('store.html')

        # if 'user' in session:
        #     # if session['user'] == 'admin@toilet.org':
        #     return render_template('admin.html')
    else:
        abort(403)


@app.route('/secret/tos')
def tos():
    return render_template('tos.html')
    # if g.user:
    #     if 'user' in session:
    #         if session['user'] == 'admin@toilet.org':
    #             return render_template('admin.html')
    #         else:
    #             abort(403)
    #
    # return redirect(url_for('login'))


@app.route('/secret')
def secret():
    return render_template('logo.html')


@app.route('/login/', methods=['GET', 'POST'])
def login():
    form = LoginForm(request.form)
    msg = ''
    if request.method == "POST" and form.validate():
        session.pop('user', None)
        email = request.form['email']
        password = request.form['password']
        print(email)
        print(password)
        statement = text('SELECT * FROM users WHERE email ="' + email + '" AND password ="' + password + '"')
        result = db.engine.execute(statement).fetchone()
        print(result)
        if result == None:
            flash('Incorrect username/password')
        else:
            session['id'] = result[0]
            session['user'] = result[3]
            session['name'] = result[1]
            session['is_authenticated'] = result[5]
            if result[3] == "admin@toilet.org":
                # blah blah blah whatever admin needs to be diff
                resp = make_response(redirect('/admin'))
            else:
                resp = make_response(redirect('/'))
            resp.set_cookie('username', result[1], httponly=False, secure=False)
            print(session['id'])
            print(session['is_authenticated'])
            return resp
        # # test = User.query.filter_by(email=email).first()
        # test = User.query.filter_by(email=email, password=password).first()
        # if test:
        # # test2 = User.query.filter_by(password=password).first()
        # # if test2:
        # # return redirect(url_for('store'))
        # # else:
        # #     msg = 'Error: Wrong Password!'
        # #     return render_template("login.html", form=form, msg=msg)

        # # if test and check_password_hash(test.password, password):
        #      if email == 'admin@toilet.org':
        #           session['user'] = 'admin@toilet.org'
        # #         access_token = create_access_token(identity=email)
        # #         print("Access token is",access_token)
        # #         print("Admin login success")
        # #         session.permanent = True
        #           return redirect(url_for('admin'))
        #      else:
        #           session['user'] = request.form['email']
        # #         access_token = create_access_token(identity=email)
        # #         print("Access token is",access_token)
        #           print("User login success")
        # # session.permanent = True
        #   return redirect(url_for('store'))
        # else:
        #     msg = 'Error: Email does not exist!'
        #     abort(401)
    return render_template("login.html", form=form, msg=msg)
    # return jsonify(message='Bad email or password'), 401


@app.route('/retrieve_password/<string:email>', methods=['GET'])
def retrieve_password(email: str):
    user = User.query.filter_by(email=email).first()
    if user:
        msg = Message("your API password is" + user.password,
                      sender="admin@aspj-api.com",
                      recipients=[email])
        mail.send(msg)
        return jsonify(message='Password sent to' + email)
    else:
        return jsonify(message="That email does not exist"), 401


if __name__ == '__main__':
    app.run(debug=True)
# app.run(debug=True, host="127.0.0.1", port=80)
