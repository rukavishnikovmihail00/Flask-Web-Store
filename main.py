from flask import Flask, render_template, request, redirect, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from cloudipsp import Api, Checkout
from werkzeug.security import check_password_hash, generate_password_hash


app = Flask(__name__)
app.secret_key = 'secretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///shop3.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
manager = LoginManager(app)


class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(80))
    price = db.Column(db.Integer, nullable=False)
    isActive = db.Column(db.Boolean, default=True)
    text = db.Column(db.Text)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String(100), index=True, unique=True)
    password = db.Column(db.String(100), index=True, unique=True)
    email = db.Column(db.String(120), index=True, unique=True)
    name = db.Column(db.String(20), nullable=False)
    surname = db.Column(db.String(30), nullable=False)
    items = db.relationship('Item', backref='author', lazy='dynamic')
    about = db.Column(db.String(140))



@manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


@app.route('/register', methods=['POST', 'GET'])
def register():
    login = request.form.get('login')
    password = request.form.get('password')
    password2 = request.form.get('password2')
    name = request.form.get('name')
    surname = request.form.get('surname')
    email = request.form.get('email')
    
    if request.method == 'POST':
        if not (login or password or password2 or name or surname or email):
            flash('Не все поля заполнены')
        elif password != password2:
            flash('Пароли не совпадают')
        else:
            hash_pwd = generate_password_hash(password)
            new_user = User(login=login, password=hash_pwd, name=name, surname=surname, email=email)
            db.session.add(new_user)
            db.session.commit()

            return redirect('/login')
    

    return render_template('register.html')


@app.route('/login', methods=['POST', 'GET'])
def login():
    login = request.form.get('login')
    password = request.form.get('password')

    if login and password:
        user = User.query.filter_by(login=login).first()

        if user and check_password_hash(user.password, password):
            login_user(user)

            next_page = request.args.get('next')

            return redirect('/auth_index')
        else:
            flash('Неверно введена пара логин-пароль')
    else:
        flash('Не все поля были заполнены')
    return render_template('login.html')


@app.route('/logout', methods=['POST', 'GET'])
@login_required
def logout():
    logout_user()
    return redirect('/')


@app.route('/')
def index():
    if current_user.is_authenticated:
        items = Item.query.order_by(Item.price).all()
        user = User.query.get(current_user.get_id())
        return render_template('auth_index.html', data=items, user=user)
    items = Item.query.order_by(Item.price).all()
    return render_template('index.html', data=items)


@app.route('/profile')
@login_required
def profile():
    user = User.query.get(current_user.get_id())
    items = user.items.order_by(Item.price.desc()).all()
    return render_template('profile.html', user=user, items=items)


@app.route('/profile/<int:id>')
def profile_check(id):
    user = User.query.get(id)
    items = user.items.order_by(Item.price.desc()).all()
    if not (current_user.is_authenticated):
        return render_template('profile_check.html', user=user, items=items)
    else:
        return render_template('profile.html', user=user, items=items)


@app.route('/add/<int:id>', methods=['POST', 'GET'])
@login_required
def add(id):
    user = User.query.filter_by(id=id).first()
    if request.method == "POST":
        title = request.form.get('title')
        price = request.form.get('price')
        user = User.query.filter_by(id=id).first()
            
        item = Item(title=title, price=price)
        user.items.append(item)
        try:
            db.session.add(item)
            db.session.commit()
        except:
            return "Что-то пошло не так"
        return redirect('/')
    return render_template('add.html', user=user)


@app.route('/auth_index')
def auth_index():
    if not (current_user.is_authenticated):
        return render_template('index.html')
    user = User.query.get(current_user.get_id())
    items = Item.query.order_by(Item.price).all()
    return render_template('auth_index.html', data=items, user=user)


@app.route('/about')
def about():
    if current_user.is_authenticated:
        user = User.query.get(current_user.get_id())
        return render_template('about_auth.html', user=user)
    return render_template('about.html')


@app.route('/about_auth')
@login_required
def about_auth():
    if not (current_user.is_authenticated):
        return render_template('about.html')
    return render_template('about_auth.html')


@app.route('/buy/<int:id>')
@login_required
def item_buy(id):
    item = Item.query.get(id)

    api = Api(merchant_id='ID', secret_key='SEKRET_KEY')
    checkout = Checkout(api=api)
    data = { "currency": "RUB", "amount": item.price*100 }
    url = checkout.url(data).get('checkout_url')
    return redirect(url)


@app.route('/create', methods=['POST', 'GET'])
@login_required
def create():
    if request.method == "POST":
        title = request.form['title']
        price = request.form['price']

        item = Item(title=title, price=price)

        try:
            db.session.add(item)
            db.session.commit()
            return redirect('/')
        except:
            return "Ошибка добавления товара. Попробуйте снова"
    else:
        return render_template('create.html')


@app.after_request
def redirect_to_signin(response):
    if response.status_code == 401:
        return redirect('/login' + '?next=' + request.url)
    
    return response


if __name__ == "__main__":
    app.run(debug=True)
