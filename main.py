from flask import Flask, render_template, request, redirect, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from cloudipsp import Api, Checkout
from werkzeug.security import check_password_hash, generate_password_hash


app = Flask(__name__)
app.secret_key = 'secretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///shop.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
manager = LoginManager(app)


class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Integer, nullable=False)
    isActive = db.Column(db.Boolean, default=True)
    # text = db.Column(db.Text, nullable=False)

    def __repr__(self):
        return self.title


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String(25), nullable=False, unique=True)
    password = db.Column(db.String(20), nullable=False)


@manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


@app.route('/register', methods=['POST', 'GET'])
def register():
    login = request.form.get('login')
    password = request.form.get('password')
    password2 = request.form.get('password2')
    
    if request.method == 'POST':
        if not (login or password or password2):
            flash('Не все поля заполнены')
        elif password != password2:
            flash('Пароли не совпадают')
        else:
            hash_pwd = generate_password_hash(password)
            new_user = User(login=login, password=hash_pwd)
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
        return render_template('auth_index.html', data=items)
    items = Item.query.order_by(Item.price).all()
    return render_template('index.html', data=items)


@app.route('/profile')
@login_required
def profile():
    user = User.query.get(current_user.get_id())
    return render_template('profile.html', user=user)



@app.route('/auth_index')
def auth_index():
    if not (current_user.is_authenticated):
        return render_template('index.html')
    items = Item.query.order_by(Item.price).all()
    return render_template('auth_index.html', data=items)


@app.route('/about')
def about():
    if current_user.is_authenticated:
        return render_template('about_auth.html')
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
