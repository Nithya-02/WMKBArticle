from flask import *
from ldap3 import *
from werkzeug.utils import secure_filename
import mysql.connector, os, secrets
from flask_auditor import FlaskAuditor

app = Flask(__name__)
app.secret_key = secrets.token_hex(8)
app.config['UPLOAD_FOLDER'] = 'uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

auditor = FlaskAuditor(app)

@app.before_request
def log_login_attempt():
    if request.endpoint == 'login' and request.method == 'POST':
        action = 'Login Attempt'
        description = 'User attempted to log in'
        auditor.log(action_id=action, description=description)

#AD Configuration
AD_SERVER = 'ldap://172.20.10.6'   
AD_DOMAIN = 'ML.com' 
ADMIN_GROUP = 'Enterprise Admins'

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
    status VARCHAR(20) DEFAULT 'Pending',
    rejection_comment TEXT
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
            connection.search(search_base='DC=ML,DC=com', search_filter=f'(sAMAccountName={username})',attributes=['cn', 'memberOf'])

            entry = connection.entries[0]
            cn = entry.cn.value
            groups = entry.memberOf
            is_admin = any(ADMIN_GROUP in group for group in groups)

            session['username'] = username
            session['cn'] = cn  
            session['is_admin'] = is_admin

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
        rejection_comment = request.form.get('rejection_comment', '').strip()

        if action == 'approve':
            cursor.execute("UPDATE ApproveKBArticle SET status = 'approved', rejection_comment = NULL WHERE id = %s", (record_id,))
        elif action == 'reject':
            cursor.execute("UPDATE ApproveKBArticle SET status = 'rejected', rejection_comment = %s WHERE id = %s", (rejection_comment, record_id))
        db.commit()

    cursor.execute("SELECT * FROM ApproveKBArticle")
    records = cursor.fetchall()

    return render_template('admin.html', records=records)

# Edit rejected article
@app.route('/edit/<int:article_id>', methods=['GET', 'POST'])
def edit_article(article_id):
    if 'cn' not in session:
        return redirect(url_for('login'))

    # Fetch the article from the database
    cursor.execute("SELECT * FROM ApproveKBArticle WHERE id = %s", (article_id,))
    article = cursor.fetchone()

    # Check if the article exists and is rejected
    if not article or article[6] != 'rejected':  # Assuming status is at index 6
        return redirect(url_for('my_articles'))

    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        url = request.form['url']
        file = request.files['file']

        # Handle file upload
        filename = article[5]  # Assuming filename is at index 5
        if file and file.filename != '':
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)

        # Update the article in the database with status as 'Pending'
        cursor.execute("""
            UPDATE ApproveKBArticle 
            SET title = %s, description = %s, url = %s, filename = %s, status = 'Pending', rejection_comment = NULL
            WHERE id = %s
        """, (title, description, url, filename, article_id))
        db.commit()

        # Redirect to the user's articles page
        return redirect(url_for('my_articles'))

    # Render the edit form with the article data
    return render_template('edit.html', article=article)


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
        
        filename = None
        if file and file.filename != '':
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)

        sql = "INSERT INTO ApproveKBArticle (name, title, description, url, filename) VALUES (%s, %s, %s, %s, %s)"
        val = (name, title, description, url, filename)
        cursor.execute(sql, val)
        db.commit()
        
        return redirect(url_for('my_articles'))

    return render_template('form.html', name=cn_name)

@app.route('/my_articles')
def my_articles():
    if 'cn' not in session:
        return redirect(url_for('login'))

    cn_name = session['cn']
    cursor.execute("SELECT * FROM ApproveKBArticle WHERE name = %s", (cn_name,))
    records = cursor.fetchall()

    return render_template('myarticles.html', records=records, name=cn_name)

@app.route('/home')
def homepage():
    if 'cn' not in session:
        return redirect(url_for('login'))
    return render_template('HomePage.html', name=session['cn'], is_admin=session.get('is_admin', False))

@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True)