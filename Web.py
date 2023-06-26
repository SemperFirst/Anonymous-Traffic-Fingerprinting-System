import os
import string
from flask import Flask, render_template,redirect,flash,url_for,jsonify
import pymysql
from flask import request
import traceback
import pymysql
from werkzeug.utils import secure_filename
from Identify import Identify
from sniFF import sniFF
from Clearfile import clearfile
app = Flask(__name__)
app.secret_key = '123456'

def get_connect():
    conn = pymysql.connect(
    host='localhost',
    user='root',
    password='123456',
    db='amtraffic',
    charset='utf8mb4',
    cursorclass=pymysql.cursors.DictCursor
    )
    return conn

conn=get_connect()
cursor=conn.cursor()
cursor.execute("SELECT COUNT(*) FROM user")
users = cursor.fetchone()
cursor.execute("SELECT COUNT(*) FROM finger")
sites = cursor.fetchone()
cursor.execute("SELECT name FROM finger limit 10")
rows=cursor.fetchall()
sitesname=[]
for row in rows:
    sitesname.append(row['name'])
    
@app.route('/')
def login():
    return render_template('login.html')

@app.route('/login',methods=['get','post'])
def getLoginRequest():
    #查询用户名及密码是否匹配及存在
    conn = get_connect()
    cursor=conn.cursor()
    user=request.args.get('user')
    password=request.args.get('password')
    sql = "select * from user where user=\"{}\" and password=\"{}\"".format(user,password)
    cursor.execute(sql)
    result = cursor.fetchone()
    if result:
        return redirect('index.html')
    else:
        return render_template('login.html',msg='用户名或密码输入错误')

@app.route('/registration.html',methods=['get','post'])
def registration():        
    return render_template('registration.html')

@app.route('/registration',methods=['get','post'])
def getregistrationrequest():        
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        #password2 = request.form.get('password2')
        data=(username, password)
        conn=get_connect()
        cursor=conn.cursor()
        insert_query = "INSERT INTO user (user, password) VALUES (%s, %s)"
        cursor.execute(insert_query, data)
        conn.commit()
        conn.close()
        return render_template('login.html',msg='注册成功')
    
@app.route('/index.html')
def index():
    return render_template('index.html',users=users['COUNT(*)'],sites=sites['COUNT(*)'],sitesname=sitesname)

@app.route('/fileAY.html')
def fileAY():
    results=Identify().fileay()
    clearfile().main()
    return render_template('fileAY.html',results=results)

@app.route('/identifybutton', methods=['POST'])
def identifybutton_clicked():
    results=Identify().main()
    #clearfile().main()
    return render_template('index.html',users=users['COUNT(*)'],sites=sites['COUNT(*)'],results=results,sitesname=sitesname)

app.config['UPLOAD_FOLDER'] = r'D:\论文code\temp'
@app.route('/uploader', methods=['POST'])
def upload_file():
    if request.method == 'POST':
        file = request.files['file']
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        filesname=Identify().get_filename()
        return render_template('index.html',users=users['COUNT(*)'],sites=sites['COUNT(*)'],filesname=filesname,sitesname=sitesname)

app.config['UPLOAD_FOLDER'] = r'D:\论文code\temp'
@app.route('/uploader2', methods=['POST'])
def upload2_file():
    if request.method == 'POST':
        ssnum = request.form.get('ssnum')
        sspro = request.form.get('sspro')
        sniFF().main(ssnum,sspro)
        filesname=Identify().get_filename()
        return render_template('index.html',users=users['COUNT(*)'],sites=sites['COUNT(*)'],filesname=filesname,sitesname=sitesname)

if __name__ == '__main__':
    app.run(debug=True)