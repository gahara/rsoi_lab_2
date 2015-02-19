from flask import *
#from session import SqliteSessionInterface
import os

app = Flask(__name__)
app.config.update(dict(
    SQLALCHEMY_DATABASE_URI='sqlite:///{0}'.format(os.path.join(app.root_path, 'second_lab.db')),
    DEBUG=True
))
app.secret_key = "key for flask"

from sqlite3 import dbapi2 as sqlite
from sqlalchemy.orm import sessionmaker, aliased

from datetime import datetime, timedelta
import hashlib, string, random

#here are  models for the db

from flask.ext.sqlalchemy import SQLAlchemy
from sqlalchemy import *

db = SQLAlchemy(app)


#user's information
class User(db.Model):
    __tablename__ = "user"
    __table_args__ = {'sqlite_autoincrement': True}
    id = db.Column(db.Integer(), primary_key = True)
    username = db.Column(db.String(100), unique=True)
    password_hash = db.Column(db.String(256))
    email = db.Column(db.String(200))
    phone = db.Column(db.String(11))
    auths = db.relationship("Authorization", cascade="all, delete-orphan")
    sessions = db.relationship("UserSession", cascade="all, delete-orphan")
    apps = db.relationship("UserApp", cascade="all, delete-orphan")
    goods = db.relationship("Good")
    comments = db.relationship("Comment")

    def to_dict(self):
        return {'username': self.username, 'password': self.password_hash, 'email': self.email, 'phone': self.phone}
    
    def __init__(self, username, password_hash, phone, email):
        self.username = username
        self.password_hash = password_hash
        self.email = email
        self.phone = phone

    def __repr__(self):
        return 'username: {0}, email: {1}, phone: {2}'.format(self.username, self.email, self.phone)

class Good(db.Model):
    __tablename__ = "good"
    __table_args__ = {'sqlite_autoincrement': True}
    id = db.Column(db.Integer(), primary_key = True)
    description = db.Column(db.String(100))
    text = db.Column(db.Text())
    author_id = db.Column(ForeignKey("user.id"), nullable=False)
    
    comments = db.relationship("Comment", cascade="all, delete-orphan")
    
    def __init__(self, user_id, description, text):
        self.author_id = user_id
        self.description = description
        self.text = text
        
    def __repr__(self):
        return 'id: {0}, author: {1}, description: {2}'.format(self.id, self.author_id, self.description)

    def to_dict(self):
        return {'id': self.id, 'author_id': self.author_id, 'description': self.description, 'text': self.text}
    

class Comment(db.Model):
    __tablename__ = "comment"
    __table_args__ = {'sqlite_autoincrement': True}
    id = db.Column(db.Integer(), primary_key = True)
    text = db.Column(db.Text())
    author_id = db.Column(ForeignKey("user.id"), nullable=False)
    good_id = db.Column(ForeignKey("good.id"), nullable=False)
    deleted = db.Column(db.Boolean(), default = False)
    
    def __init__(self, user_id, good_id, text):
        self.author_id = user_id
        self.good_id = good_id
        self.text = text
        
    def __repr__(self):
        return 'id: {0}, author: {1}'.format(self.id, self.author_id)

    def to_dict(self):
        return {'id': self.id, 'author_id': self.author_id, 'good_id': self.good_id, 'text': self.text if not self.deleted else '', 'deleted': self.deleted}
        
    def delete(self):
        self.deleted = True
    

def make_random_string(size):
    return ''.join([random.choice(string.ascii_letters) for i in range(size)])

class UserSession(db.Model):
    __tablename__ = "usersession"
    __table_args__ = {'sqlite_autoincrement': True}
    id = db.Column(db.Integer(), primary_key = True)
    user_id = db.Column(ForeignKey("user.id"), nullable=False)
    session_id = db.Column(db.String(32), unique = True)
    
    def __init__(self, user):
        self.session_id = make_random_string(32)
        self.user_id = user.id

class AppCode(db.Model):
    __tablename__ = "appcode"
    __table_args__ = {'sqlite_autoincrement': True}
    id = db.Column(db.Integer(), primary_key = True)
    code = db.Column(db.String(32), unique = True)
    timestamp = db.Column(db.DateTime)
    client_id = db.Column(ForeignKey("UserApp.id"), nullable=False)
    auth_id = db.Column(ForeignKey("authorization.id"))
    lifetime_min = 2
    
    def __init__(self, UserApp):
        self.code = make_random_string(32)
        self.client_id = UserApp.id
        self.timestamp = datetime.utcnow()
        
    def is_valid(self):
        return (self.timestamp - datetime.utcnow()) < timedelta(minutes = self.lifetime_min)

class UserApp(db.Model):
    __tablename__ = "UserApp"
    __table_args__ = {'sqlite_autoincrement': True}
    id = db.Column(db.Integer(), primary_key = True)
    client_id = db.Column(db.String(32), unique = True)
    secret_id = db.Column(db.String(256), unique = True)
    redirect_uri = db.Column(db.String(100))
    user_id = db.Column(ForeignKey("user.id"), nullable=False)
    
    appcodes = db.relationship("AppCode", cascade="all, delete-orphan")
    
    def __init__(self, redirect_uri, user_id):
        self.client_id = make_random_string(32)
        self.secret_id = hashlib.sha256(make_random_string(32).encode('utf-8')).hexdigest()
        self.redirect_uri = redirect_uri
        self.user_id = user_id
        
    def __repr__(self):
        return 'cl_id: {0}, username: {1}, redir_uri: {2}'.format(self.client_id, self.username, self.redirect_uri)
    
    def to_dict(self):
        return {'cl_id': self.client_id, 'secret_id': self.secret_id, 'username': self.username, 'redirect_uri': self.redirect_iri}

class Authorization(db.Model):
    __tablename__ = "authorization"
    __table_args__ = {'sqlite_autoincrement': True}
    id = db.Column(db.Integer(), primary_key = True)
    access_token = db.Column(db.String(32), unique=True)
    refresh_token = db.Column(db.String(32), unique=True)
    timestamp = db.Column(db.DateTime)
    user_id = db.Column(ForeignKey("user.id"), nullable=False)
    
    appcodes = db.relationship("AppCode", cascade="all, delete-orphan")
    
    def __init__(self, user):
        self.user_id = user.id
        self.token_refresh()
        
    def __repr__(self):
        return 'cl_id: {0}, access_token: {1}, authorized: {2}, ts: {3}'.format(self.client_id, self.access_token, self.is_authorized, self.timestamp)
    
    
    def authorize(self):
        if not self.access_token:
            self.token_refresh()
    
    def token_refresh(self):
        self.access_token = make_random_string(32)
        self.refresh_token = make_random_string(32)
        self.timestamp = datetime.utcnow()
        
    def token_expired(self):
        return (self.timestamp - datetime.utcnow()) >= timedelta(hours = 1)

    def authorized(self):
        return not self.token_expired()

        
###

def get_url_parameter(name):
    rjson = request.get_json()
    if name in request.args:
        return request.args[name]
    elif name in request.form:
        return request.form[name]
    elif name in request.headers:
        return request.headers[name]
    elif rjson:
        if name in rjson:
            return rjson[name]
    else:
        return None
                                                                             
def has_url_parameter(name):
    rjson = request.get_json()
    part = (name in request.args) or (name in request.form) or (name in request.headers)
    return ((name in rjson) and part) if rjson else part

def get_access_token():
    if has_url_parameter('Authorization'):
        ah = get_url_parameter('Authorization')
        t, token = ah.split(' ')
        if t == 'bearer':
            return token
        else:
            return None
    else:
        return get_url_parameter('access_token')


def response_builder(r, s):
    resp = jsonify(r)
    resp.status_code = s
    return resp

#Http responses
@app.errorhandler(200)
def ok_200(data = {}):
    return response_builder(data, 200)

@app.errorhandler(400)
def err_400(msg = 'Bad Request'):
    return response_builder({'error': msg}, 400)

@app.errorhandler(401)
def err_401(msg = 'Not authorized'):
    return response_builder({'error': msg}, 401)

@app.errorhandler(403)
def err_403(msg = 'Forbidden'):
    return response_builder({'error': msg}, 403)

@app.errorhandler(404)
def err_404(msg = 'Not found'):
    return response_builder({'error': msg}, 404)



#Views

@app.route('/index', methods=['GET'])
def root():
    return 'Welcome to the shop! Here you can buy or sell things to the other users.'

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    
    if request.method == 'POST':
        username = get_url_parameter('username')
        password = get_url_parameter('password')
        
        user = User.query.filter_by(username = username).first()
        if user:
            s = UserSession(user)
            db.session.add(s)
            db.session.commit()
            
            resp = None
            if has_url_parameter('back_to_code'):
                resp = redirect(url_for('code', session_id = s.session_id))
            else:
                resp = ok_200({'session_id' : s.session_id})
            resp.set_cookie('session_id', s.session_id)
            return resp
        else:
            error = 'User not found'
            
    if (has_url_parameter('back_to_code')):        
        return render_template(\
            'login.html',\
            error=error,\
            back_to_code = True,\
            client_id = get_url_parameter('client_id'),\
            secret_id = get_url_parameter('secret_id'),\
            state = get_url_parameter('state')\
        )
    else:
        return render_template('login.html', error=error, back_to_code = False)

@app.route('/logout', methods=['POST'])
def logout():
    if has_url_parameter('session_id'):
        s_id = get_url_parameter('session_id')
        s = UserSession.query.filter_by(session_id = s_id).first()
        if s:
            db.session.delete(s)
            db.session.commit()
            return ok_200()
        else:
            return err_401()
    else:
        return err_400('Parameters required: session_id')

@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        username = get_url_parameter('username')
        password = hashlib.sha256(get_url_parameter('password').encode('utf-8')).hexdigest()
        email = get_url_parameter('email')
        phone = get_url_parameter('phone')
        
        if not User.query.filter_by(username = username).all():
            user = User(username, password, email, phone)
            db.session.add(user)
            db.session.commit()
            return ok_200()
        else:
            error = 'User already exists'
    return render_template('register.html', error=error)

@app.route('/register_app', methods=['POST'])
def register_app():
    if has_url_parameter('session_id') and has_url_parameter('redirect_uri'):
        s_id = get_url_parameter('session_id')
        r_uri = get_url_parameter('redirect_uri')
                
        s = UserSession.query.filter_by(session_id = s_id).first()
        if s:
            app_ = UserApp(r_uri, s.user_id)
            db.session.add(app_)
            db.session.commit()
            return ok_200({'client_id': app_.client_id, 'secret_id': app_.secret_id})
        else:
            return err_401()
    else:
        return err_400('Parameters required: session_id, redirect_uri')

@app.route('/code', methods=['GET'])
def code():
    s = UserSession.query.filter_by(session_id = request.cookies.get('session_id')).first()
    if has_url_parameter('client_id') and has_url_parameter('secret_id') and has_url_parameter('state'):
        state = get_url_parameter('state')
        cl_id = get_url_parameter('client_id')
        s_idh = get_url_parameter('secret_id')
        
    else:
        return err_400('Parameters required: client_id, secret_id, state')
    if s:      
        app_ = UserApp.query.filter_by(client_id = cl_id, secret_id = s_idh).first()
        if app_:
            code = AppCode(app_)
            db.session.add(code)    
            db.session.commit()    
            return redirect(app_.redirect_uri + '?state={0}&code={1}&lifetime_minutes={2}'.format(state, code.code, code.lifetime_min))
        else:
            return err_401('Invalid client_id - secret_id pair')
    else:
        return redirect(url_for('login', back_to_code = True, client_id = cl_id, secret_id = s_idh, state = state))

@app.route('/access_token', methods=['GET'])
def access_token():
    app_ = None
    if has_url_parameter('code') and has_url_parameter('client_id') and has_url_parameter('secret_id'):
        code = get_url_parameter('code')
        cl_id = get_url_parameter('client_id')
        sech = get_url_parameter('secret_id')
        code = AppCode.query.filter_by(code = code).first()
        if code:
            if code.is_valid():
                app_ = UserApp.query.filter_by(id = code.client_id, client_id = cl_id, secret_id = sech).first()
            else:
                return err_401('Code is no more valid')
            
    if app_:
        auth = Authorization.query.join(AppCode, AppCode.auth_id == Authorization.id).filter(AppCode.id == code.id).first()
        if not auth:
            auth = Authorization(app_)
            db.session.add(auth)
            db.session.commit()
        return ok_200({'access_token' : auth.access_token, 'refresh_token' : auth.refresh_token})
    else:
        return err_401()
        
@app.route('/refresh_token', methods=['POST'])
def refresh_token():
    app_ = None
    if has_url_parameter('client_id') and has_url_parameter('secret_id'):
        app_ = UserApp.query.filter_by(client_id = get_url_parameter('client_id'), secret_id = get_url_parameter('secret_id')).first()
    if app_:
        if has_url_parameter('refresh_token'):
            rt = get_url_parameter('refresh_token')
            auth = Authorization.query.filter_by(refresh_token = rt).first()
            if auth:
                auth.token_refresh()
                db.session.commit()
                return ok_200({'access_token' : auth.access_token, 'refresh_token' : auth.refresh_token})
        else:
            return err_400('Parameters required: client_id, secret_id, refresh_token')
    return err_401()
    
@app.route('/revoke_token', methods=['POST'])
def revoke_token():
    app_ = None
    if has_url_parameter('client_id') and has_url_parameter('secret_id'):
        app_ = UserApp.query.filter_by(client_id = get_url_parameter('client_id'), secret_id = get_url_parameter('secret_id')).first()
    if app_:
        if has_url_parameter('refresh_token'):
            rt = get_url_parameter('refresh_token')
            auth = Authorization.query.filter_by(refresh_token = rt).first()
            if auth:
                db.session.delete(auth)
                db.session.commit()
                return ok_200()
        else:
            return err_400('Parameters required: client_id, secret_id, refresh_token')
    return err_401()

@app.route('/me', methods=['GET'])
def me():
    at = get_access_token()
    auth = Authorization.query.filter_by(access_token = at).first()
    if auth:
        if auth.authorized():
            user = User.query.filter_by(id = auth.user_id).first()
            retv = user.to_dict()
            return ok_200(retv)
    return err_401('Not authorized or token expired')

@app.route('/authorized_users', methods=['GET'])
def authorized_users():
    apps = User.query.join(Authorization, Authorization.user_id == User.id).filter(Authorization.is_authorized == True).all()
    return ok_200({'Authorized_users':[c.username for c in apps]})


def is_authorized(auth):
    if auth:
        return auth.authorized()
    return False

# Goods

@app.route('/goods', methods=['GET'])
def get_goods():
    if has_url_parameter('author_un'):        
        author = get_url_parameter('author_un')
        goods = Good.query\
            .join(User.goods)\
            .filter(User.username == author)\
            .all()
        return ok_200({'Goods': [p.to_dict() for p in goods]})
    else:
        return ok_200({'Goods': [p.to_dict() for p in Good.query.all()]})

@app.route('/goods', methods=['POST'])
def post_good():
    auth = Authorization.query.filter_by(access_token = get_access_token()).first()
    if is_authorized(auth):
        user = User.query.filter_by(id = auth.user_id).first()
        description = get_url_parameter('description')
        text = get_url_parameter('text')
        p = Good(user.id, description, text)
        db.session.add(p)
        db.session.commit()
        return ok_200({'good_id': p.id})
    else:
        return err_403()

@app.route('/goods/<int:good_id>', methods=['GET'])
def get_good(good_id):
    p = Good.query.filter_by(id = good_id).first()
    return ok_200(p.to_dict()) if p else err_404() 

@app.route('/goods/<int:good_id>', methods=['PUT'])
def put_good(good_id):
    auth = Authorization.query.filter_by(access_token = get_access_token()).first()
    if is_authorized(auth):
        g = Good.query.filter_by(id = good_id).first()
        if g:
            user = User.query.filter_by(id = auth.user_id).first()
            author = get_url_parameter('author_un')
            if (user.username == author):
                description = get_url_parameter('description')
                g.description = description
                text = get_url_parameter('text')
                g.text = text
                db.session.commit()
                return ok_200()
            else:
                return err_403()
        return err_404()
    return err_401('Not authorized or token expired')

@app.route('/goods/<int:good_id>', methods=['DELETE'])
def del_good(good_id):
    auth = Authorization.query.filter_by(access_token = get_access_token()).first()
    if is_authorized(auth):
        g = Good.query.filter_by(id = good_id).first()
        if g:
            user = User.query.filter_by(id = auth.user_id).first()
            db.session.delete(p)
            db.session.commit()
            return ok_200()
            
        else:
            return err_404()
    return err_401('Not authorized or token expired')

# Comments

@app.route('/comments', methods=['GET'])
def get_comments():
    g_id = get_url_parameter('good_id')
    res_per_page = get_url_parameter('res_per_page')
    cnt = get_url_parameter('limit')
    offset = get_url_parameter('offset')
    cs = None
    if has_url_parameter('author_un'):        
        author = get_url_parameter('author_un')
        cs = Comment.query\
            .join(User.comments)\
            .filter(User.username == author)\
            .filter(Comment.good_id == g_id)\
            .offset(offset).limit(cnt)\
            .all()
    else:
        cs = Comment.query.filter(Comment.good_id == g_id).offset(offset).limit(cnt).all()
    retv = []
    results_per_page = int(res_per_page)
    for i, c in enumerate(cs):
        page = int(i / results_per_page)
        crepr = c.to_dict()
        crepr.update({'page': page})
        retv += [crepr]
    return ok_200({'Comments': retv})

@app.route('/comments', methods=['POST'])
def post_comment():
    
    auth = Authorization.query.filter_by(access_token = get_access_token()).first()
    if is_authorized(auth):
        user = User.query.filter_by(id = auth.user_id).first()
        g_id = get_url_parameter('good_id')
        text = get_url_parameter('text')
        c = Comment(user.id, g_id, text)
        db.session.add(c)
        db.session.commit()
        return ok_200({'comment_id': c.id})
    else:
        return err_403()

@app.route('/comments/<int:comment_id>', methods=['GET'])
def get_comment(comment_id):
    c = Comment.query.filter_by(id = comment_id).first()
    return ok_200(c.to_dict()) if c else api_404()

@app.route('/comments/<int:comment_id>', methods=['PUT'])
def put_comment(comment_id):
    auth = Authorization.query.filter_by(access_token = get_access_token()).first()
    if is_authorized(auth):
        user = User.query.filter_by(id = auth.user_id).first()
        
        text = get_url_parameter('text')
        c = Comment.query.filter_by(id = comment_id).first()
        if c:
            if not c.deleted:
                c.text = text
                db.session.commit()
                return ok_200()
            else:
                return err_403('Comment was deleted')
            else:
                return err_404()
        else:
            return err_403()
    return err_401('Not authorized or token expired')

@app.route('/comments/<int:comment_id>', methods=['DELETE'])
def del_comment(comment_id):
    auth = Authorization.query.filter_by(access_token = get_access_token()).first()
    if is_authorized(auth):
        user = User.query.filter_by(id = auth.user_id).first()
        
        text = get_url_parameter('text')
        c = Comment.query.filter_by(id = comment_id).first()
        if c:
            c.delete()
            db.session.commit()
            return ok_200()
        else:
            return err_404()
        else:
            return err_403()
    return err_401('Not authorized or token expired')

### Other ###

if __name__ == '__main__':
    app.run()
    
### Testing ###
