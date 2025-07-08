# Import necessary libraries
from flask import *
from ldap3 import *
from werkzeug.utils import secure_filename
import mysql.connector, os, secrets
from flask_auditor import FlaskAuditor
from fuzzywuzzy import fuzz
import smtplib
import ssl
from email.message import EmailMessage
import re

# Initialize Flask application
app = Flask(__name__, static_folder='static', template_folder='templates')
app.secret_key = secrets.token_hex(8)
app.config['UPLOAD_FOLDER'] = 'uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

auditor = FlaskAuditor(app)

PORT = 25
SMTP_Name = "smtp.freesmtpservers.com"
CONTEXT = ssl.create_default_context()
FROM = 'nhari@freesmtpservers.com'

# Configure Flask Auditor
@app.before_request
def log_login_attempt():
    if request.endpoint == 'login' and request.method == 'POST':
        action = 'Login Attempt'
        description = 'User attempted to log in'
        auditor.log(action_id=action, description=description)

#AD Configuration
AD_SERVER = 'ldap://192.168.86.209'   
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

# Create ApproveKBArticle table if not exists
cursor.execute("""
CREATE TABLE IF NOT EXISTS ApproveKBArticle (
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
            connection.search(search_base='DC=ML,DC=com', search_filter=f'(sAMAccountName={username})', attributes=['cn', 'memberOf'])

            entry = connection.entries[0]
            cn = entry.cn.value
            groups = entry.memberOf

            group_names = []
            is_admin = False
            is_kb_approver = False

            for dn in groups:
                match = re.search(r'CN=([^,]+)', dn)
                if match:
                    group_name = match.group(1)
                    group_names.append(group_name)
                    if group_name == 'Enterprise Admins':
                        is_admin = True
                    elif group_name == 'KBApprove':
                        is_kb_approver = True

            session['username'] = username
            session['cn'] = cn
            session['is_admin'] = is_admin
            session['is_kb_approver'] = is_kb_approver
            session['groups'] = group_names

            return redirect(url_for('homepage'))

        except Exception as e:
            message = "Failed to Login! Invalid AD credentials"

    return render_template('login.html', message=message)

# Configure Admin route
@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if 'cn' not in session or not (session.get('is_admin') or session.get('is_kb_approver')):
        return redirect(url_for('login'))
    if request.method == 'POST':
        action = request.form['action']
        cn_name = session['cn']
        title = request.form.get('title')
        apname = request.form.get('apname')
        record_id = int(request.form['record_id'])
        rejection_comment = request.form.get('rejection_comment', '').strip()

        if action == 'approve':
            cursor.execute("UPDATE ApproveKBArticle SET status = 'approved', rejection_comment = NULL WHERE id = %s", (record_id,))
            try:
                msg = EmailMessage()
                TO = ["nhari@freesmtpservers.com"]
                SUBJECT = f"Article Approved : {title}"
                TEXT = f"""
                <html>  
                <body>
                <p>Dear {apname},</p>
                <p>Your Article <b>{title}</b> has been approved.</p>
                <p>Thanks & Regards,</p>
                <p>{cn_name}</p>
                </body>
                </html>
                """
                msg['Subject'] = SUBJECT
                msg['From'] = FROM
                msg['To'] = ', '.join(TO)
                msg.set_content(TEXT, subtype="html")      
                server = smtplib.SMTP(SMTP_Name, PORT)
                server.send_message(msg)
                server.quit()
                print("✅ Article is approved and email sent to user.")
            except Exception as e:
                print("❌ Error sending email:", str(e))
        elif action == 'reject':
            cursor.execute("UPDATE ApproveKBArticle SET status = 'rejected', rejection_comment = %s WHERE id = %s", (rejection_comment, record_id))
            try:
                msg = EmailMessage()
                TO = ["nhari@freesmtpservers.com"]
                SUBJECT = f"Article Rejected : {title}"
                TEXT = f"""
                <html>  
                <body>
                <p>Dear {apname},</p>
                <p>Your Article <b>{title}</b> has been rejected. Please find the below comments from Approver & Make the Necessary Changes.</p>
                <p><strong>Rejection Comment:</strong> {rejection_comment}</p>
                <p>If you have any questions, please feel free to reach out.</p>
                <p>Thanks & Regards,</p>
                <p>{cn_name}</p>
                </body>
                </html>
                """
                msg['Subject'] = SUBJECT
                msg['From'] = FROM
                msg['To'] = ', '.join(TO)
                msg.set_content(TEXT, subtype="html")      
                server = smtplib.SMTP(SMTP_Name, PORT)
                server.send_message(msg)
                server.quit()
                print("✅ Article is rejected and email sent to user.")
            except Exception as e:
                print("❌ Error sending email:", str(e))
        db.commit()

    cursor.execute("SELECT * FROM ApproveKBArticle")
    records = cursor.fetchall()

    return render_template('admin.html', records=records)

# Configure super admin route
@app.route('/grant_permissions', methods=['GET', 'POST'])
def grant_permissions():
    if 'cn' not in session or not session.get('is_admin'):
        return redirect(url_for('login'))
    message = None
    name = session['cn']
    if request.method == 'POST':
        user_id = request.form.get('user_id')
        action = request.form.get('action')

        if action == 'add':
            try:
                # Setup LDAP connection
                server = Server(AD_SERVER, get_info=ALL)
                conn = Connection(
                    server,
                    user='ML.com\\Administrator',
                    password='Shannu@2007',
                    authentication=NTLM,
                    auto_bind=True
                )

                user_id = user_id.strip()
                if not user_id:
                    message = "User ID cannot be empty."
                    return render_template('grant_permissions.html', message=message)

                # Step 1: Search for user's DN using sAMAccountName
                search_base = 'DC=ML,DC=com'
                search_filter = f'(sAMAccountName={user_id})'
                conn.search(search_base, search_filter, attributes=['distinguishedName'])

                if not conn.entries:
                    message = f"User with ID '{user_id}' not found in Active Directory."
                else:
                    user_dn = conn.entries[0].distinguishedName.value
                    group_dn = f'CN=KBApprove,CN=Users,DC=ML,DC=com'

                    # Step 2: Add user to the group
                    conn.modify(group_dn, {'member': [(MODIFY_ADD, [user_dn])]})

                    if conn.result['result'] == 0:
                        message = f"✅ User {user_id} has been granted the KBApprover role."
                    else:
                        message = f"❌ Failed to add user {user_id} to the group. Error: {conn.result['description']}"

                conn.unbind()

            except Exception as e:
                message = f"An error occurred: {str(e)}"

        elif action == 'remove':
            try:
                # Setup LDAP connection
                server = Server(AD_SERVER, get_info=ALL)
                conn = Connection(
                    server,
                    user='ML.com\\Administrator',
                    password='Shannu@2007',
                    authentication=NTLM,
                    auto_bind=True
                )

                user_id = user_id.strip()
                if not user_id:
                    message = "User ID cannot be empty."
                    return render_template('grant_permissions.html', message=message)

                # Step 1: Search for user's DN using sAMAccountName
                search_base = 'DC=ML,DC=com'
                search_filter = f'(sAMAccountName={user_id})'
                conn.search(search_base, search_filter, attributes=['distinguishedName'])

                if not conn.entries:
                    message = f"❌ User with ID '{user_id}' not found in Active Directory."
                else:
                    user_dn = conn.entries[0].distinguishedName.value
                    group_dn = f'CN=KBApprove,CN=Users,DC=ML,DC=com'

                    # Step 2: Remove user from the group
                    conn.modify(group_dn, {'member': [(MODIFY_DELETE, [user_dn])]})

                    if conn.result['result'] == 0:
                        message = f"✅ User {user_id}'s KBApprover role has been revoked."
                    else:
                        message = f"❌ Failed to remove user {user_id} from the group. Error: {conn.result['description']}"

                conn.unbind()

            except Exception as e:
                message = f"An error occurred: {str(e)}"
            pass
    cursor.execute("SELECT COUNT(*) FROM ApproveKBArticle WHERE name = %s AND status = 'approved'", (name,))
    approveCount = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM ApproveKBArticle WHERE name = %s AND status = 'rejected'", (name,))
    rejectCount = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM ApproveKBArticle WHERE name = %s", (name,))
    totalCount = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM ApproveKBArticle WHERE name = %s AND status = 'Pending'", (name,))
    pendingCount = cursor.fetchone()[0]

    return render_template('grant_permissions.html', name=name, is_admin=session.get('is_admin', False), is_kb_approver=session.get('is_kb_approver', False),
    approveCount=approveCount,
    rejectCount=rejectCount,
    totalCount=totalCount,
    pendingCount=pendingCount,
    message=message
)



########################################### ROUTES FOR HOMEPAGE AND ARTICLE MANAGEMENT ##############################################

# Homepage
@app.route('/home')
def homepage():
    if 'cn' not in session:
        return redirect(url_for('login'))

    name = session['cn']
    is_admin = session.get('is_admin', False)
    is_kb_approver = session.get('is_kb_approver', False)
    all_articles = []

    if is_admin or is_kb_approver:
        cursor.execute("SELECT * FROM ApproveKBArticle")
        all_articles = cursor.fetchall()
    
    cursor.execute("SELECT COUNT(*) FROM ApproveKBArticle WHERE name = %s AND status = 'approved'", (name,))
    approveCount = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM ApproveKBArticle WHERE name = %s AND status = 'rejected'", (name,))
    rejectCount = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM ApproveKBArticle WHERE name = %s", (name,))
    totalCount = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM ApproveKBArticle WHERE name = %s AND status = 'Pending'", (name,))
    pendingCount = cursor.fetchone()[0]
    
    return render_template('HomePage.html', name=name, is_admin=is_admin, is_kb_approver=is_kb_approver,records=all_articles, 
                           approveCount=approveCount, rejectCount=rejectCount, 
                           totalCount=totalCount, pendingCount=pendingCount)

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
        group = request.form['groups']
        file = request.files['file']
        
        filename = None
        if file and file.filename != '':
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)

        # Generate custom article ID like HR-001
        prefix = group[:3].upper()
        cursor.execute("""
            SELECT COUNT(*) FROM ApproveKBArticle WHERE ADGroups LIKE %s
        """, (f'%{group}%',))
        count = cursor.fetchone()[0] + 1
        article_id = f"{prefix}-{count:03d}"


        sql = "INSERT INTO ApproveKBArticle (name, title, description, url, filename, ADGroups, article_id_custom) VALUES (%s, %s, %s, %s, %s, %s, %s)"
        val = (name, title, description, url, filename, group, article_id)
        cursor.execute(sql, val)
        db.commit()

        try:
            msg = EmailMessage()
            TO = ["nhari@freesmtpservers.com"]
            SUBJECT = "New KB Article Submitted by " + cn_name
            TEXT = f"""
            <html>  
            <body>
            <p>Dear Approvers,</p>
            <p>A new KB article has been submitted by {cn_name}.</p>
            <p><strong>Title:</strong> {title}</p>
            <p><strong>Description:</strong> {description}</p>
            <p><strong>Filename:</strong> {filename if filename else 'No file uploaded'}</p>
            <p>Please review and take necessary action.</p>
            <p>Thanks & Regards,</p>
            <p>{cn_name}</p>
            </body>
            </html>
            """
            msg['Subject'] = SUBJECT
            msg['From'] = FROM
            msg['To'] = ', '.join(TO)
            msg.set_content(TEXT, subtype="html")      
            server = smtplib.SMTP(SMTP_Name, PORT)
            server.send_message(msg)
            server.quit()
            print("✅ Email sent to approvers.")
        except Exception as e:
            print("❌ Error sending email:", str(e))
        
        flash(f"✅ Article submitted successfully! Article ID: {article_id}", "success")
        return redirect(url_for('submit'))

    return render_template('form.html', name=cn_name, groups=groups)

# MY ARTICLES
@app.route('/my_articles')
def my_articles():
    if 'cn' not in session:
        return redirect(url_for('login'))

    cn_name = session['cn']
    cursor.execute("SELECT * FROM ApproveKBArticle WHERE name = %s", (cn_name,))
    records = cursor.fetchall()

    cursor.execute("SELECT COUNT(*) FROM ApproveKBArticle WHERE name = %s AND status = 'approved'", (cn_name,))
    approveCount = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM ApproveKBArticle WHERE name = %s AND status = 'rejected'", (cn_name,))
    rejectCount = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM ApproveKBArticle WHERE name = %s", (cn_name,))
    totalCount = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM ApproveKBArticle WHERE name = %s AND status = 'Pending'", (cn_name,))
    pendingCount = cursor.fetchone()[0]

    return render_template('myarticles.html', records=records, name=cn_name, 
                           approveCount=approveCount, rejectCount=rejectCount, 
                           totalCount=totalCount, pendingCount=pendingCount)

@app.route('/my_articles/approved')
def approved_articles():
    if 'cn' not in session:
        return redirect(url_for('login'))

    cn_name = session['cn']
    cursor.execute("SELECT * FROM ApproveKBArticle WHERE name = %s AND status = 'approved'", (cn_name,))
    records = cursor.fetchall()

    cursor.execute("SELECT COUNT(*) FROM ApproveKBArticle WHERE name = %s AND status = 'approved'", (cn_name,))
    approveCount = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM ApproveKBArticle WHERE name = %s AND status = 'rejected'", (cn_name,))
    rejectCount = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM ApproveKBArticle WHERE name = %s", (cn_name,))
    totalCount = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM ApproveKBArticle WHERE name = %s AND status = 'Pending'", (cn_name,))
    pendingCount = cursor.fetchone()[0]

    return render_template('approve.html', records=records, name=cn_name, 
                           approveCount=approveCount, rejectCount=rejectCount, 
                           totalCount=totalCount, pendingCount=pendingCount)

@app.route('/my_articles/rejected')
def rejected_articles():
    if 'cn' not in session:
        return redirect(url_for('login'))

    cn_name = session['cn']
    cursor.execute("SELECT * FROM ApproveKBArticle WHERE name = %s AND status = 'rejected'", (cn_name,))
    records = cursor.fetchall()

    cursor.execute("SELECT COUNT(*) FROM ApproveKBArticle WHERE name = %s AND status = 'approved'", (cn_name,))
    approveCount = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM ApproveKBArticle WHERE name = %s AND status = 'rejected'", (cn_name,))
    rejectCount = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM ApproveKBArticle WHERE name = %s", (cn_name,))
    totalCount = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM ApproveKBArticle WHERE name = %s AND status = 'Pending'", (cn_name,))
    pendingCount = cursor.fetchone()[0]

    return render_template('reject.html', records=records, name=cn_name, 
                           approveCount=approveCount, rejectCount=rejectCount, 
                           totalCount=totalCount, pendingCount=pendingCount)

@app.route('/my_articles/pending')
def pending_articles(): 
    if 'cn' not in session:
        return redirect(url_for('login'))

    cn_name = session['cn']
    cursor.execute("SELECT * FROM ApproveKBArticle WHERE name = %s AND status = 'Pending'", (cn_name,))
    records = cursor.fetchall()

    cursor.execute("SELECT COUNT(*) FROM ApproveKBArticle WHERE name = %s AND status = 'approved'", (cn_name,))
    approveCount = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM ApproveKBArticle WHERE name = %s AND status = 'rejected'", (cn_name,))
    rejectCount = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM ApproveKBArticle WHERE name = %s", (cn_name,))
    totalCount = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM ApproveKBArticle WHERE name = %s AND status = 'Pending'", (cn_name,))
    pendingCount = cursor.fetchone()[0]

    return render_template('pending.html', records=records, name=cn_name, approveCount=approveCount, 
                           rejectCount=rejectCount, totalCount=totalCount, pendingCount=pendingCount)

# EDIT REJECTED ARTICLE
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

# SEARCH ARTICLES
def search_articles(query):
    cursor.execute("""
        SELECT id, title, description
        FROM ApproveKBArticle
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

    cursor.execute("SELECT * FROM ApproveKBArticle WHERE id = %s", (article_id,))
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

    cursor.execute("SELECT * FROM ApproveKBArticle WHERE id = %s", (article_id,))
    article = cursor.fetchone()

    if not article:
        return redirect(url_for('my_articles')) 
    # Render the edit form with the article data
    return render_template('view_myarticle.html', article=article)

@app.route('/get_next_article_id', methods=['POST'])
def get_next_article_id():
    data = request.get_json()
    group = data.get('group')

    if not group:
        return jsonify({'error': 'Group not provided'}), 400

    # Extract numeric suffixes from title for that group (if any used previously)
    cursor.execute("""
        SELECT MAX(id)
        FROM ApproveKBArticle
        WHERE ADGroups LIKE %s
    """, (f"%{group}%",))

    result = cursor.fetchone()
    max_id = result[0] if result and result[0] else 0
    next_id = max_id + 1

    return jsonify({'next_article_id': next_id})

#  VIEW PDF
@app.route('/view_pdf/<filename>')
def view_pdf(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

################################### ARTICLE MANAGEMENT ROUTES ###################################

# Logout - Connection
@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True)