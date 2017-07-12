from flask import Flask, request, redirect, render_template, session, flash
from flask_bcrypt import Bcrypt
from mysqlconnection import MySQLConnector
import re, md5
app = Flask(__name__)
app.secret_key = 'ThisIsSecret'
bcrypt = Bcrypt(app)
mysql = MySQLConnector(app,'loginregistrationdb')

@app.route('/', methods=['GET'])
def index():                      
    return render_template('index.html')

#CREATE

@app.route('/register', methods=['POST'])
def create():
    email = request.form['email']
    password = request.form['password']
    password_confirmation = request.form['confirm_password']
    email_match = re.match('^[_a-z0-9-]+(\.[_a-z0-9-]+)*@[a-z0-9-]+(\.[a-z0-9-]+)*(\.[a-z]{2,4})$', email)
    first_match = re.match('[A-Za-z]', request.form['first_name'])
    last_match = re.match('[A-Za-z]', request.form['last_name'])
    user_query = "SELECT * FROM users WHERE email = :email LIMIT 1"
    query_data = { 'email': email }
    user = mysql.query_db(user_query, query_data)
    session['error'] = ""
    if (session['name'] != None) and (session['name'] != ""):
        session['error'] = 'please logout'
        return redirect('/')
    elif (session['id'] != None) and (session['id'] != ""):
        session['error'] = 'please logout'
        return redirect('/')
    elif len(user) < 1:
        try:
            if len(request.form['password']) < 8:
                session['reqs'] = 1
                return redirect('/')
            elif len(request.form['first_name']) < 2:
                session['reqs'] = 1
                return redirect('/')
            elif len(request.form['last_name']) < 2:
                session['reqs'] = 1
                return redirect('/')
            elif first_match == None:
                session['reqs'] = 1
                return redirect('/')
            elif last_match == None:
                session['reqs'] = 1
                return redirect('/')
            elif email_match == None:
                session['reqs'] = 1
                return redirect('/')
            else:
                pw_hash = bcrypt.generate_password_hash(password)
                if bcrypt.check_password_hash(pw_hash, password_confirmation) is False:
                    session['error'] = 'passwords do not match'
                    return redirect('/')
                elif bcrypt.check_password_hash(pw_hash, password_confirmation) is True:
                    insert_query = "INSERT INTO users (first_name, last_name, email, password, created_at, updated_at) \
                        VALUES (:first_name, :last_name, :email, :pw_hash, NOW(), NOW())"
                    query_data = {
                            'first_name': request.form['first_name'],
                            'last_name':  request.form['last_name'],
                            'email': email,
                            'pw_hash': bcrypt.generate_password_hash(password)
                        }
                    mysql.query_db(insert_query, query_data)
                    userid_query = "SELECT * FROM users WHERE email = :email LIMIT 1"
                    idquery_data = { 'email': email }
                    userid = mysql.query_db(userid_query, idquery_data)
                    session['name'] = request.form['first_name']
                    session['id'] = userid[0]['id']
                    session['error'] = ""
                    session['reqs'] = ""
                    return redirect('/success')
        except IndexError:
            session['error'] = "unknown error"
            session['reqs'] = ""
            return redirect('/')
    else:
        session['error'] = 'email already registered'
        return redirect('/')

#READ

@app.route('/login', methods=['POST'])
def login():
    try:
        email = request.form['email']
        password = request.form['password']
        user_query = "SELECT * FROM users WHERE email = :email LIMIT 1"
        query_data = { 'email': email }
        user = mysql.query_db(user_query, query_data)
        if (session['name'] != None) and (session['name'] != ""):
            session['error'] = 'please logout'
            return redirect('/')
        elif (session['id'] != None) and (session['id'] != ""):
            session['error'] = 'please logout'
            return redirect('/')
        elif bcrypt.check_password_hash(user[0]['password'], password):
            session['name'] = str(user[0]['first_name'])
            session['id'] = user[0]['id']
            session['error'] = ""
            session['reqs'] = ""
            return redirect('/success')  
        else:
            print 'invalid login'
            session['error'] = "invalid login"
            session['reqs'] = ""
            return redirect('/')
    except IndexError:
            print 'invalid login'
            session['error'] = "invalid login"
            session['reqs'] = ""
            return redirect('/')

@app.route('/success', methods=['GET'])
def success():
    try:
        if (session['id'] == "") or (session['name'] == ""):
            session['error'] = "no one is logged in"
            session['reqs'] = ""
            return redirect('/')
        else:
            session['error'] = ""
            return render_template('success.html')
    except KeyError:
        session['id'] = ""
        session['name'] = ""
        session['error'] = ""
        return redirect('/')

@app.route('/logout', methods=['GET'])
def logout():
    session['id'] = ""
    session['name'] = ""
    session['error'] = ""
    return redirect('/')

#UPDATE

    #NO UPDATE REQ FOR THIS ASSIGNMENT

#DELETE

    #NO DELETE REQ FOR THIS ASSIGNMENT

app.run(debug=True)