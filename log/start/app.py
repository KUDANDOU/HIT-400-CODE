from flask import Flask, render_template, redirect, url_for,request
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.file import FileField, FileRequired, FileAllowed
from flask_uploads import UploadSet, configure_uploads, IMAGES, patch_request_class
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import os
from werkzeug import secure_filename



UPLOAD_FOLDER = 'E:\projects'
ALLOWED_EXTENSIONS = set(['txt','exe'])


app = Flask(__name__)
app.config.update(dict(
    SECRET_KEY="powerful secretkey",
    WTF_CSRF_SECRET_KEY="a csrf secret key"
))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
Bootstrap(app)
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'



class User(db.Model):
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique= True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# adding forms
class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('remember me')
class RegisterForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    username = StringField('username', validators=[InputRequired(), Length(min=8, max=80)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])

class UploadForm(FlaskForm):
    executable = FileField(validators=[FileAllowed(exe, u'Executables only!'), FileRequired(u'File was empty!')])
    submit = SubmitField(u'Upload')


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS




@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        file = request.files['file']
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            return redirect(url_for('index'))
   
    return render_template('index.html')

@app.route('/login', methods= ['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember= form.remember.data)
                return redirect(url_for('dashboard'))
        
        return '<h1>Invalid username and password </h1>'
        #return'<h1>' + form.username.data  + ' ' + form.password.data + '</h1>'



    return render_template('login.html',form=form)

@app.route('/signup', methods= ['GET', 'POST'] )
def signup():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method = 'sha256')
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user) 
        db.session.commit()


        return '<h1>New user has been created!</h1>'
        #return'<h1>' + form.username.data  + ' ' + form.email.data + ' ' + form.password.data + '</h1>'

    return render_template('signup.html', form=form)

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)