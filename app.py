from flask import *
from ldap3 import *
from werkzeug.utils import secure_filename
import mysql.connector, os, secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(8)
app.config['UPLOAD_FOLDER'] = 'uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

#AD Configuration
AD_SERVER = 'ldap://192.168.86.239'   
AD_DOMAIN = 'ML.com' 

#DB Configuration
db = mysql.connector.connect(
    host="localhost",
    user="root",
    password="varudhini1979",
    database="kbarticle"
)
cursor = db.cursor()

# Create table if not exists
cursor.execute("""
CREATE TABLE IF NOT EXISTS ApproveKBArticle (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100),
    title VARCHAR(500),
    description TEXT,
    url VARCHAR(255),
    filename VARCHAR(255),
    status VARCHAR(20) DEFAULT 'Pending'
)
""")
db.commit()

#Login - Connection
@app.route('/', methods=['GET', 'POST'])
def login():
    message = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user_dn = f"{AD_DOMAIN}\\{username}"

        try:
            server = Server(AD_SERVER, get_info=ALL)
            connection = Connection(server, user=user_dn, password=password, authentication=NTLM, auto_bind=True)
            connection.search(search_base='DC=ML,DC=com', search_filter=f'(sAMAccountName={username})',attributes=['cn'])

            cn = connection.entries[0].cn.value if connection.entries else 'Unknown'

            session['username'] = username
            session['cn'] = cn  

            return redirect(url_for('homepage'))
        
        except Exception as e:
            message="Failed to Login! Invalid AD credentials"

    return render_template('login.html', message = message)

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if 'cn' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        action = request.form['action']
        record_id = int(request.form['record_id'])

        if action == 'approve':
            cursor.execute("UPDATE ApproveKBArticle SET status = 'approved' WHERE id = %s", (record_id,))
            db.commit()
        elif action == 'reject':
            cursor.execute("DELETE FROM ApproveKBArticle WHERE id = %s", (record_id,))
            db.commit()

    cursor.execute("SELECT * FROM ApproveKBArticle")
    records = cursor.fetchall()

    return render_template('admin.html', records=records)


#Form Submit
@app.route('/submit', methods=['GET', 'POST'])
def submit():
    if 'cn' not in session:
        return redirect(url_for('login'))
    
    cn_name = session['cn']
    if request.method == 'POST':
        name = cn_name
        title = request.form['title']
        description = request.form['description']
        url = request.form['url']
        file = request.files['file']
        
        if file:
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)

        sql = "INSERT INTO ApproveKBArticle (name, title, description, url, filename) VALUES (%s, %s, %s, %s, %s)"
        val = (name, title, description, url, filename)
        cursor.execute(sql, val)
        db.commit()
        
        return render_template('form.html',name=cn_name, message="Form submitted successfully!")

    return render_template('form.html', name=cn_name)

@app.route('/home')
def homepage():
    if 'cn' not in session:
        return redirect(url_for('login'))
    return render_template('HomePage.html', name=session['cn'])

if __name__ == '__main__':
    app.run(debug=True)