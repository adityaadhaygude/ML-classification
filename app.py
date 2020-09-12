from flask import Flask, render_template, redirect, url_for, request, session,escape
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm 
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy  import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import os


app = Flask(__name__)
app.config['SECRET_KEY'] = 'Thisissupposedtobesecret!'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:@localhost/flask-login'
bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
user_manager = LoginManager()
login_manager.init_app(app)
user_manager.init_app(app)
login_manager.login_view = 'login'
user_manager.login_view = 'userlogin'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))

class Users(UserMixin,db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20))
    nationality = db.Column(db.String(20))
    phone = db.Column(db.Integer)
    validity = db.Column(db.Integer)
    username = db.Column(db.String(20), unique=True)
    password = db.Column(db.String(20))
    status = db.Column(db.Integer)
    num_of_runs = db.Column(db.Integer)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@user_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))

class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=4, max=150)])
    remember = BooleanField('remember me')

class UserLoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=4, max=150)])
    remember = BooleanField('remember me')

class RegisterForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=4, max=15)])

class CreateUserForm(FlaskForm):
    name = StringField('name', validators=[InputRequired(), Length(max=20)])
    nationality = StringField('nationality', validators=[InputRequired(), Length(max=20)])
    phone = StringField('mobile number', validators=[InputRequired(), Length(max=10)])
    validity = StringField('validity', validators=[InputRequired(), Length(max=20)])
    username = StringField('username', validators=[InputRequired(), Length(max=20)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=4, max=15)])

@app.route('/', methods=['GET','POST'])
def userlogin():
    form = UserLoginForm()
    msg=""
    if form.validate_on_submit():
        user = Users.query.filter_by(username=form.username.data).first()
        if user:
            if (user.password == form.password.data):
                if user.status == 1:
                    login_user(user, remember=form.remember.data)
                    return redirect(url_for('predict'))
                else:
                    msg = 'Your account is deactivated contact with administrator!'
                    return render_template('userlogin.html',form=form,msg=msg)
            
        msg = 'Invalid username or password'
    return render_template('userlogin.html',form=form,msg=msg)

@app.route('/predict',methods=['GET','POST'])
@login_required
# @limiter.limit(runs+"/day",error_message=error_handler())
def predict():
    import interface
    user = Users.query.filter_by(username=current_user.username,status='1').first()
    msg = ""
    if request.method == 'POST':
        if user.num_of_runs>0:
            uploaded_file = request.files['file']
            if uploaded_file.filename != '':
                image_path = os.path.join('static',uploaded_file.filename)
                uploaded_file.save(image_path)
                msg = interface.get_prediction(image_path)
                Users.query.filter_by(username=current_user.username).update(dict(num_of_runs=user.num_of_runs-1))
                db.session.commit()
                return render_template('result.html',msg=msg, img=image_path)
        msg = "Daily program run limit exceeds try by tommarrow!"
    return render_template('predict.html', msg=msg)

@app.route('/admin')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if (user.password == form.password.data):
                session['username'] = form.username.data
                login_user(user, remember=form.remember.data)
                return redirect(url_for('dashboard'))

        return '<h1>Invalid username or password</h1>'
    return render_template('login.html', form=form)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = form.password.data
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        return '<h1>New user has been created!</h1>'
        #return '<h1>' + form.username.data + ' ' + form.email.data + ' ' + form.password.data + '</h1>'

    return render_template('signup.html', form=form)

@app.route('/dashboard')
@login_required
def dashboard(): 
    if 'username' in session:
      username = session['username']
    data = Users.query.all()
    return render_template('dashboard.html', name=username , data=data)

@app.route('/createuser', methods=['GET', 'POST'])
@login_required
def createuser():
    form = CreateUserForm()
    if form.validate_on_submit():
        name = form.name.data
        nationality = form.nationality.data
        phone = form.phone.data
        validity = form.validity.data
        username = form.username.data
        password = form.password.data
        new_user = Users(name=name, nationality=nationality, phone=phone, validity=validity, username=username, password=password)
        db.session.add(new_user)
        db.session.commit()
        return '<h1>New user has been created!</h1>'
    return render_template('createuser.html', name=session['username'] , form=form)

@app.route('/limituser')
@login_required
def limituser():
    data = Users.query.all()
    return render_template('limituser.html', name=session['username'], data=data)

@app.route('/activateuser/<int:id>', methods=['GET','POST'])
@login_required
def activateuser(id):
    if(request.method == 'POST'):
        data = Users.query.filter_by(id=id).update(dict(status='1'))
        db.session.commit()
        return redirect(url_for('limituser'))

@app.route('/deactivateuser/<int:id>', methods=['GET','POST'])
@login_required
def deactivateuser(id):
    if(request.method == 'POST'):
        data = Users.query.filter_by(id=id).update(dict(status='0'))
        db.session.commit()
        return redirect(url_for('limituser'))

@app.route('/deleteuser')
@login_required
def deleteuser():
    data = Users.query.all()
    return render_template('deleteuser.html', name=session['username'], data=data)

@app.route('/deleteuser/<int:id>', methods=['GET','POST'])
@login_required
def removeuser(id):
    data = Users.query.filter_by(id=id).delete()
    db.session.commit()
    return redirect(url_for('deleteuser'))

@app.route('/numofruns')
@login_required
def numofruns():
    data = Users.query.all()
    return render_template('numofruns.html', name=session['username'], data=data)

@app.route('/changenumofruns/<int:id>', methods=['GET','POST'])
@login_required
def changenumofruns(id):
    if request.method == 'POST':
        runs = request.form['runs']
        data = Users.query.filter_by(id=id).update(dict(num_of_runs=runs))
        db.session.commit()
        return redirect(url_for('numofruns'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.pop('logged_user', None)
    return redirect(url_for('index'))

@app.route('/userlogout')
@login_required
def userlogout():
    logout_user()
    return redirect(url_for('userlogin'))

if __name__ == '__main__':
    app.run(debug=True)