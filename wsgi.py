# -- coding:utf-8 --

from flask import Flask, g, render_template, request, redirect, url_for, session
from gevent.pywsgi import WSGIServer
import sqlite3, datetime, time, hashlib

app = Flask(__name__)
app.secret_key = 'key'
DATABASE = './db/board.db'

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db

def init_db():
    with app.app_context():
        db = get_db()
        f = open('schema.sql','r')
        db.execute(f.read())
        db.commit()

def register(user_id, password, name, email, mobile):
    qu = u"INSERT INTO users (user_id,password,name,email,mobile) VALUES ('{}','{}','{}','{}','{}')".format(user_id, password, name, email, mobile)
    db = get_db()
    db.execute(qu)
    db.commit()

def fo(col):
    return request.form.get(col)


@app.route('/welcome', methods=['GET','POST'])
def welcome():
    if request.method == "GET":
        return render_template('welcome.html')
    elif request.method == "POST":
        u = fo('user_id')
        p = hashlib.sha256(fo('password')).hexdigest()
        n = fo('name')
        em = fo('email')
        mo = fo('mobile')
        for fd in [u,p,n,em,mo]:
            if len(fd) < 1:
                 return alert()
        register(u, p, n, em, mo)
        return '''
               <script>
               alert('환영합니다!');
               location.replace('/');
               </script>
               '''

def get_user(u):
    qu = "SELECT * FROM users WHERE user_id='{}'".format(u)
    db = get_db()
    rv = db.execute(qu)
    res = rv.fetchall()
    return res[0]

@app.route('/secret',methods=['GET','POST'])
def secret():
    if 'username' in session:
         if request.method == 'GET':
              data = get_user(session['username'])
              return render_template('secret.html', data=data)
         elif request.method == 'POST':
              data = get_user(session['username'])
              qu = [u"UPDATE users SET "]
              info = {'password':fo('password'),'name':fo('name'),'email':fo('email'),'mobile':fo('mobile')}
              for d1,d2 in info.items():
                   if len(d2) < 1:
                       continue
                   else:
                       if len(qu) == 1:
                           qu[0] = qu[0] + u"{}='{}'".format(d1,d2)
                       else:
                           qu[0] = qu[0] + u",{}='{}'".format(d1,d2)
              if not(len(qu) == 1):
                 commit_db(qu[0])
              return redirect(url_for('main'))
    else: 
        return alert2()  
              
@app.route('/confirm',methods=['GET','POST'])
def cofirm_pw():
     if 'username' in session:
         if request.method == 'GET':
             return render_template('confirm.html')
         elif request.method == 'POST':
             p = hashlib.sha256(fo('password')).hexdigest()
             data = get_user(session['username'])
             if p == data[1]:
                 return redirect(url_for('secret'))
             else:
                 return alert2()
     else:
         return alert2()   

@app.route('/', methods=['GET','POST'])
def index():
    if request.method == "GET":
        return render_template('login.html')
    elif request.method == "POST":
        u = fo('user_id')
        p = hashlib.sha256(fo('password')).hexdigest()
        for userinfo in [u,p]:
            if len(userinfo) < 1:
                return alert2()
            else:
                if login_check(u,p):
                    session['username'] = u
                    return redirect(url_for('main'))
                else:
                    return alert1()

@app.route('/main', methods=['GET'])
def main():
    if 'username' in session:
        if request.method == "GET":
            data = get_post(None)
            return render_template('main.html', data=data)
    else:
        return alert1()   

def login_check(u,p): 
    qu = "SELECT * FROM users WHERE user_id='{}' AND password='{}'".format(u,p)
    db = get_db()
    rv = db.execute(qu)
    res = rv.fetchall()
    if res:
        return True
    else:
        return False
   
@app.route('/logout',methods=['GET'])
def logout():
     if 'username' in session:
        session.pop('username',None)
        return '''
               <script>
               alert('다시 로그인하세요');
               location.replace('/');
               </script>
               '''
     else:
          return alert1()

def timestamp():
    ct = time.time()
    ts = datetime.datetime.fromtimestamp(ct).strftime('%Y-%m-%d %H:%M:%S')
    return ts

@app.route('/write', methods=['GET','POST'])
def write_post():
    if 'username' in session:
        if request.method == "GET":
            return render_template('write.html')
        elif request.method == "POST":
            ti = fo('title')
            co = fo('content')
            idx = get_idx() + 1 
            for data in [ti, co]:
                if len(data) < 1:
                     return alert2()
                            
            qu = u"INSERT INTO board (idx,title,content,writer,ctime) VALUES ({}, '{}','{}','{}','{}')".format(idx, ti, co, session['username'], timestamp())
            commit_db(qu)
            return redirect(url_for('main'))
    else:   
            return alert2()

@app.route('/main/del/<idx>',methods=['GET'])
def del_post(idx):
    if 'username' in session:
        qu = "DELETE FROM board WHERE idx={}".format(idx)
        commit_db(qu)
        return redirect(url_for('main'))
    else:
        return alert2()

@app.route('/main/modi/<idx>',methods=['GET','POST'])
def mod_post(idx):
    if 'username' in session:
        if request.method == "GET":
            data = get_post(idx)
            return render_template('modi.html',data=data)
        elif request.method == "POST":
           ti = fo('title')
           co = fo('content')
           data = get_post(idx)
           if len(co) < 1:
               qu = u"UPDATE board SET title='{}',content='{}' WHERE idx={}".format(ti,data[0][2],idx)
               commit_db(qu)
               return redirect(url_for('main'))
           elif len(ti) < 1:
               qu = u"UPDATE board SET title='{}',content='{}' WHERE idx={}".format(data[0][1],co,idx)
               commit_db(qu)
               return redirect(url_for('main'))
           else:
               qu = u"UPDATE board SET title='{}', content='{}' WHERE idx={}".format(ti,co,idx)
               commit_db(qu)
               return redirect(url_for('main'))
                   
    else:
        return alert2()

@app.route('/main/view/<idx>',methods=['GET'])
def view_post(idx):
    qu = 'SELECT * FROM board WHERE idx={}'.format(idx)
    db = get_db()
    rv= db.execute(qu)
    res = rv.fetchall()
    if session['username'] == res[0][3]:
        return render_template('view.html',data=res,perm=session['username'])
    else: 
        return render_template('view.html',data=res,perm=None)

def get_post(idx):
    if idx is None:
       qu = "SELECT * FROM board"
    else:
       qu = "SELECT * FROM board where idx={}".format(idx)    
    db = get_db()
    rv = db.execute(qu)
    res = rv.fetchall()
    return res

def get_idx():
    r = get_post(None)
    try:
        return int(r[-1][0])
    except IndexError:
        return 0

def commit_db(qu):
    db = get_db()
    db.execute(qu)
    db.commit()

def alert1():
    return '''
           <script>
           alert('다시 시도하세요');
           location.replace('/');
           </script>
           '''

def alert2():
    return '''
           <script>
           alert('잘못된 접근입니다');
           history.go(-1);
           </script>
           '''

if __name__ == "__main__":
#    init_db()
    app.run(host='0.0.0.0')
