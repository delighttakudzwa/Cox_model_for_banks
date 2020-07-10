from flask import Flask, render_template, redirect, url_for, request, jsonify
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm 
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy  import SQLAlchemy
# from werkzeug import secure_filename
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

import pandas as pd
import pickle
import numpy as np

app = Flask(__name__)
app.config['SECRET_KEY'] = 'Thisissupposedtobesecret!'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///../database.db' 
bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

app.config['UPLOAD_FOLDER'] = "."
app.config['MAX_CONTENT_PATH'] = "1000000"

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('remember me')

class RegisterForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/dashboard1')
@login_required
def dashboard1():
    return render_template('dashboard1.html')

@app.route("/predict_new_bank", methods=["GET", "POST"])
@login_required
def predict_new_bank():

    if request.method == "POST":
        total_deposits_to_total_assets = request.form.get("total_deposits_to_total_assets")
        total_loan_and_advance_to_total_assets = request.form.get("total_loan_and_advance_to_total_assets")
        cons_net_income_to_average_total_assests = request.form.get("cons_net_income_to_average_total_assests")
        operating_expenses_to_total_assets = request.form.get("operating_expenses_to_total_assets")
        NPL_to_average_total_assets = request.form.get("NPL_to_average_total_assets")
        NPL_to_total_loan_and_lease = request.form.get("NPL_to_total_loan_and_lease")
        total_loans_and_advance_to_total_deposits = request.form.get("total_loans_and_advance_to_total_deposits")

        new_prediction = np.array([total_deposits_to_total_assets,
                                   total_loan_and_advance_to_total_assets,
                                   cons_net_income_to_average_total_assests,
                                   operating_expenses_to_total_assets,
                                   NPL_to_average_total_assets,
                                   NPL_to_total_loan_and_lease,
                                   total_loans_and_advance_to_total_deposits,1])

        pkl_filename = "cox_ph_fitter.mod"
        with open(pkl_filename, 'rb') as file:
            cph = pickle.load(file)

            a=cph.predict_survival_function(new_prediction)

            print(a)

    return render_template("predict_new_bank.html")

@app.route('/view_excel', methods=['GET', 'POST'])
@login_required
def view_excel():
    #response = jsonify({'some': 'data'})
    #response.headers.add('Access-Control-Allow-Origin', '*')
    if request.method == "POST":
        #excel_file = request.files["excel_file"]
        #excel_file.save(secure_filename(excel_file.filename))
        df = pd.read_excel("data2.xlsx")
        #banks = df.bank_name
        #banks.tolist()
        banks=df.values.tolist()
        print(banks)
        # Load from file
        pkl_filename = "cox_ph_fitter.mod"
        with open(pkl_filename, 'rb') as file:
            cph = pickle.load(file)

            print(cph.summary)
        return render_template("results.html", banks=banks)
    return render_template('view_excel2.html')
 

@app.route('/browse', methods=['GET', 'POST'])
@login_required
def browse():
    if request.method == "POST":
        excel_file = request.files["excel_file"]
        #excel_file.save(secure_filename(excel_file.filename))
        df = pd.read_excel(excel_file)
        return df.to_html()
    return render_template('browse.html')        

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                return redirect(url_for('dashboard1'))

        return '<h1>Invalid username or password</h1>'
        #return '<h1>' + form.username.data + ' ' + form.password.data + '</h1>'

    return render_template('login.html', form=form)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        return '<h1>New user has been created!</h1>'
        #return '<h1>' + form.username.data + ' ' + form.email.data + ' ' + form.password.data + '</h1>'

    return render_template('signup.html', form=form)

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', name=current_user.username)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
