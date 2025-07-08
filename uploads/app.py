# Import necessary libraries
from flask import *
from ldap3 import *
from werkzeug.utils import secure_filename
import mysql.connector, os, secrets
from flask_auditor import FlaskAuditor
from fuzzywuzzy import fuzz
import re

# Initialize Flask application
app = Flask(__name__)
app.secret_key = secrets.token_hex(8)
app.config['UPLOAD_FOLDER'] = 'uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

auditor = FlaskAuditor(app)

# Configure Flask Auditor
@app.before_request
def log_login_attempt():
    if request.endpoint == 'login' and request.method == 'POST':
        action = 'Login Attempt'
        description = 'User attempted to log in'
        auditor.log(action_id=action, description=description)

#AD Configuration
AD_SERVER = 'ldap://172.18.10.67'   
AD_DOMAIN = 'test1234.com' 
ADMIN_GROUP = 'Enterprise Admins'

#DB Configuration
db = mysql.connector.connect(
    host="localhost",
    user="root",
    password="Dad@2001",
    database="final"
)
cursor = db.cursor()

# Create ApproveKBArticle1a table if not exists
cursor.execute("""
CREATE TABLE IF NOT EXISTS ApproveKBArticle1a (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100),
    title VARCHAR(500),
    description TEXT,
    url VARCHAR(255),
    filename VARCHAR(255),
    status VARCHAR(20) DEFAULT 'Pending',
    rejection_comment TEXT,
    ADGroups TEXT
)
""")
db.commit()

########################################### CONNECTION ROUTES(Login, Admin, Super Admin) ##############################################

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
            connection.search(search_base='DC=test1234,DC=com', search_filter=f'(sAMAccountName={username})',attributes=['cn', 'memberOf'])

            entry = connection.entries[0]
            cn = entry.cn.value
            groups = entry.memberOf
            is_admin = any(ADMIN_GROUP in group for group in groups)

            group_names = []
            for dn in groups:
                match = re.search(r'CN=([^,]+)', dn)
                if match:
                    group_names.append(match.group(1))

            session['username'] = username
            session['cn'] = cn  
            session['is_admin'] = is_admin
            session['groups'] = group_names

            return redirect(url_for('homepage'))
        
        except Exception as e:
            message="Failed to Login! Invalid AD credentials"

    return render_template('login.html', message = message)

@app.route('/grant_permissions', methods=['GET', 'POST'])
def grant_permissions():
    if 'cn' not in session or not session.get('is_admin'):
        return redirect(url_for('login'))

    message = None
    if request.method == 'POST':
        user_id = request.form.get('user_id')
        action = request.form.get('action')

        if action == 'add':
            try:
                # Define the AD server and credentials
                server = Server('ldap://172.18.10.67', get_info=ALL)
                conn = Connection(server, user='test1234.com\\administrator', password='xxxxx', authentication=NTLM, auto_bind=True)

                # Define the Distinguished Name (DN) of the user and the group
                user_dn = f'CN={user_id},CN=Users,DC=test1234,DC=com'
                group_dn = 'CN=Enterprise Admins,CN=Users,DC=test1234,DC=com'

                # Add the user to the group
                conn.modify(group_dn, {'member': [(MODIFY_ADD, [user_dn])]})

                if conn.result['result'] == 0:
                    message = f"User {user_id} has been added to the Enterprise Admins group."
                else:
                    message = f"Failed to add user {user_id} to the Enterprise Admins group. Error: {conn.result['description']}"

                conn.unbind()

            except Exception as e:
                message = f"An error occurred: {str(e)}"

        elif action == 'remove':
            # Implement removal logic here
            pass

        elif action == 'view':
            # Implement view members logic here
            pass

    return render_template('grant_permissions.html', message=message)




# Configure Admin route
@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if 'cn' not in session or not session.get('is_admin'):
        return redirect(url_for('login'))

    if request.method == 'POST':
        action = request.form['action']
        record_id = int(request.form['record_id'])
        rejection_comment = request.form.get('rejection_comment', '').strip()

        if action == 'approve':
            cursor.execute("UPDATE ApproveKBArticle1a SET status = 'approved', rejection_comment = NULL WHERE id = %s", (record_id,))
        elif action == 'reject':
            cursor.execute("UPDATE ApproveKBArticle1a SET status = 'rejected', rejection_comment = %s WHERE id = %s", (rejection_comment, record_id))
        db.commit()

    cursor.execute("SELECT * FROM ApproveKBArticle1a")
    records = cursor.fetchall()

    return render_template('admin.html', records=records)
# Configure super admin route


########################################### ROUTES FOR HOMEPAGE AND ARTICLE MANAGEMENT ##############################################

# Homepage
@app.route('/home')
def homepage():
    if 'cn' not in session:
        return redirect(url_for('login'))

    name = session['cn']
    is_admin = session.get('is_admin', False)

    if is_admin:
        cursor.execute("SELECT * FROM ApproveKBArticle1a")
        all_articles = cursor.fetchall()
    else:
        all_articles = []

    return render_template('HomePage.html', name=name, is_admin=is_admin, records=all_articles)

################################### ARTICLE MANAGEMENT ROUTES ###################################

# SUBMIT ARTICLE
@app.route('/submit', methods=['GET', 'POST'])
def submit():
    if 'cn' not in session:
        return redirect(url_for('login'))
    
    cn_name = session['cn']
    groups = session.get('groups', [])
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

        sql = "INSERT INTO ApproveKBArticle1a (name, title, description, url, filename, ADGroups) VALUES (%s, %s, %s, %s, %s, %s)"
        val = (name, title, description, url, filename, ','.join(groups))
        cursor.execute(sql, val)
        db.commit()
        
        return redirect(url_for('my_articles'))

    return render_template('form.html', name=cn_name, groups=groups)

# MY ARTICLES
@app.route('/my_articles')
def my_articles():
    if 'cn' not in session:
        return redirect(url_for('login'))

    cn_name = session['cn']
    cursor.execute("SELECT * FROM ApproveKBArticle1a WHERE name = %s", (cn_name,))
    records = cursor.fetchall()

    return render_template('myarticles.html', records=records, name=cn_name)

# EDIT REJECTED ARTICLE
@app.route('/edit/<int:article_id>', methods=['GET', 'POST'])
def edit_article(article_id):
    if 'cn' not in session:
        return redirect(url_for('login'))

    # Fetch the article from the database
    cursor.execute("SELECT * FROM ApproveKBArticle1a WHERE id = %s", (article_id,))
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
            UPDATE ApproveKBArticle1a 
            SET title = %s, description = %s, url = %s, filename = %s, status = 'Pending', rejection_comment = NULL
            WHERE id = %s
        """, (title, description, url, filename, article_id))
        db.commit()
        # Redirect to the user's articles page
        return redirect(url_for('my_articles'))
    # Render the edit form with the article data
    return render_template('edit.html', article=article)

# SEARCH ARTICLES
def search_articles(query):
    cursor.execute("""
        SELECT id, title, description
        FROM ApproveKBArticle1a
        WHERE status = 'approved'
        AND MATCH(title, description) AGAINST (%s IN NATURAL LANGUAGE MODE)
        ORDER BY MATCH(title, description) AGAINST (%s IN NATURAL LANGUAGE MODE) DESC
        LIMIT 20
    """, (query, query))
    results = cursor.fetchall()
    return [{'id': row[0], 'title': row[1]} for row in results]

@app.route('/search')
def search():
    query = request.args.get('q', '')
    if not query:
        return jsonify({'error': 'Query parameter "q" is required'}), 400
    results = search_articles(query)
    return jsonify(results)

# VIEW MY ARTICLE(FROM MY ARTICLES PAGE)
@app.route('/view_article/<int:article_id>')
def view_article(article_id):
    if 'cn' not in session:
        return redirect(url_for('login'))

    cursor.execute("SELECT * FROM ApproveKBArticle1a WHERE id = %s", (article_id,))
    article = cursor.fetchone()

    if not article:
        return redirect(url_for('my_articles')) 
    # Render the edit form with the article data
    return render_template('view_article.html', article=article)

# VIEW MY ARTICLE(FROM SEARCH)
@app.route('/view_myarticle/<int:article_id>')
def view_myarticle(article_id):
    if 'cn' not in session:
        return redirect(url_for('login'))

    cursor.execute("SELECT * FROM ApproveKBArticle1a WHERE id = %s", (article_id,))
    article = cursor.fetchone()

    if not article:
        return redirect(url_for('my_articles')) 
    # Render the edit form with the article data
    return render_template('view_myarticle.html', article=article)

#  VIEW PDF
@app.route('/view_pdf/<filename>')
def view_pdf(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# Logout - Connection
@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True)