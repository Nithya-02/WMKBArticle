# Import necessary libraries
from flask import *
from ldap3 import *
from collections import OrderedDict
from datetime import datetime
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
FROM = 'test1@freesmtpservers.com'

# Configure Flask Auditor
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

cursor.execute(""" 
CREATE TABLE IF NOT EXISTS KBApprovers ( 
id INT AUTO_INCREMENT PRIMARY KEY, 
username TEXT UNIQUE NOT NULL, 
granted_at DATETIME DEFAULT CURRENT_TIMESTAMP 
) 
""") 
db.commit() 

cursor.execute("""
CREATE TABLE IF NOT EXISTS groups_kbarticle (
    id INT AUTO_INCREMENT PRIMARY KEY,
    group_name VARCHAR(255) UNIQUE NOT NULL
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
            print(f"[INFO] Attempting login for: {user_dn}")

            # Step 1: Connect to AD server
            try:
                server = Server(AD_SERVER, get_info=ALL)
                print("[INFO] Created AD server object.")
            except Exception as e:
                print("[ERROR] Failed to create AD server object.")
                raise RuntimeError(f"AD server connection error: {str(e)}")

            # Step 2: Try binding
            try:
                connection = Connection(
                    server,
                    user=user_dn,
                    password=password,
                    authentication=NTLM,
                    auto_bind=True
                )
                print("[INFO] Successfully bound to AD.")
            except Exception as e:
                print("[ERROR] Failed to bind to AD with given credentials.")
                raise RuntimeError(f"AD bind error: {str(e)}")

            # Step 3: Search for user in AD
            try:
                connection.search(
                    search_base='DC=ML,DC=com',  # <-- kept from your first code
                    search_filter=f'(sAMAccountName={username})',
                    attributes=['cn', 'sAMAccountName', 'memberOf']
                )
                print("[INFO] AD search executed.")
            except Exception as e:
                print("[ERROR] AD search failed.")
                raise RuntimeError(f"AD search error: {str(e)}")

            # Step 4: Validate user existence
            if not connection.entries:
                print("[WARN] User not found in AD search results.")
                message = "Login failed: User not found in AD."
                return render_template('login.html', message=message)

            # Step 5: Extract user info
            entry = connection.entries[0]
            cn = entry.cn.value
            username = entry.sAMAccountName.value
            groups = entry.memberOf
            group_names = []
            is_admin = False

            for g in groups:
                if 'CN=' in g:
                    group_name = g.split(',')[0].split('=')[1]
                    group_names.append(group_name)
                    if group_name == ADMIN_GROUP:
                        is_admin = True

            # Step 6: Check KBApprovers table
            try:
                print(f"[INFO] Checking KBApprover DB for: {cn}")
                cursor.execute("SELECT username FROM KBApprovers WHERE username = %s", (username,))
                session['is_kb_approver'] = bool(cursor.fetchone())
                print(f"[INFO] Is KB Approver: {session['is_kb_approver']}")
            except Exception as e:
                print("[ERROR] Database query failed for KBApprovers.")
                raise RuntimeError(f"DB query error: {str(e)}")

            # Step 7: Store session data
            session['groups'] = group_names
            session['username'] = username
            session['cn'] = cn
            session['is_admin'] = is_admin

            print(f"[INFO] Login successful for {username}")
            return redirect(url_for('homepage'))

        except Exception as e:
            import traceback
            traceback.print_exc()
            message = f"Failed to Login! Error: {str(e)}"

    return render_template('login.html', message=message)

# Configure Admin route
@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if 'cn' not in session or not (session.get('is_admin') or session.get('is_kb_approver')):
        return redirect(url_for('login'))
    name = session['cn']
    if request.method == 'POST':
        action = request.form['action']
        record_id = int(request.form['record_id'])
        rejection_comment = request.form.get('rejection_comment', '').strip()

        if action == 'approve':
            cursor.execute("UPDATE ApproveKBArticle SET status = 'approved', rejection_comment = NULL WHERE id = %s", (record_id,))
            message = "✅ Article Approved successfully!"
        elif action == 'reject':
            cursor.execute("UPDATE ApproveKBArticle SET status = 'rejected', rejection_comment = %s WHERE id = %s", (rejection_comment, record_id))
            message = "❌ Article Rejected and reverted for changes!"
        db.commit()

    cursor.execute("SELECT COUNT(*) FROM ApproveKBArticle WHERE name = %s AND status = 'approved'", (name,))
    approveCount = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM ApproveKBArticle WHERE name = %s AND status = 'rejected'", (name,))
    rejectCount = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM ApproveKBArticle WHERE name = %s", (name,))
    totalCount = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM ApproveKBArticle WHERE name = %s AND status = 'Pending'", (name,))
    pendingCount = cursor.fetchone()[0]
    cursor.execute("SELECT * FROM ApproveKBArticle")
    records = cursor.fetchall()

    return render_template('admin.html', name=name, is_admin=session.get('is_admin', False), is_kb_approver=session.get('is_kb_approver', False),
        message=message if 'message' in locals() else None,
        approveCount=approveCount,
        rejectCount=rejectCount,
        totalCount=totalCount,
        pendingCount=pendingCount,
        records=records
    )

@app.route('/grant_approver', methods=['POST'])
def grant_approver():
    if not session.get('is_admin'):
        return jsonify({'status': 'error', 'message': 'Unauthorized'}), 403
    cn_to_grant = request.form.get('user_cn', '').strip()
    if not cn_to_grant:
        return jsonify({'status': 'error', 'message': 'User CN required'}), 400
    try:
        cursor.execute("INSERT IGNORE INTO KBApprovers (username) VALUES (%s)", (cn_to_grant,))
        db.commit()
        return jsonify({'status': 'success', 'message': f'{cn_to_grant} granted approver'}), 200
    except Exception as e:
        db.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/revoke_approver', methods=['POST'])
def revoke_approver():
    if not session.get('is_admin'):
        return jsonify({'status': 'error', 'message': 'Unauthorized'}), 403
    cn_to_revoke = request.form.get('user_cn', '').strip()
    if not cn_to_revoke:
        return jsonify({'status': 'error', 'message': 'User CN required'}), 400
    try:
        cursor.execute("DELETE FROM KBApprovers WHERE username = %s", (cn_to_revoke,))
        db.commit()
        return jsonify({'status': 'success', 'message': f'{cn_to_revoke} revoked approver'}), 200
    except Exception as e:
        db.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/grant_permissions', methods=['GET', 'POST'])
def grant_permissions():
    if 'cn' not in session or not session.get('is_admin'):
        return redirect(url_for('login'))
    message = None
    if request.method == 'POST':
        action = request.form.get('action')
        user_cn = request.form.get('user_id', '').strip()
        try:
            if action == 'add':
                cursor.execute("INSERT IGNORE INTO KBApprovers (username) VALUES (%s)", (user_cn,))
                db.commit()
                message = f"✅ KB Article Approver Access GRANTED : {user_cn}"
            elif action == 'remove':
                cursor.execute("DELETE FROM KBApprovers WHERE username = %s", (user_cn,))
                db.commit()
                message = f"✅ KB Article Approver Access REVOKED : {user_cn}"
            else:
                message = "❌ Invalid action"
            if 'cn' in session and session['cn'] == user_cn:
                session['is_kb_approver'] = (action == 'add')
        except Exception as e:
            db.rollback()
            message = f"❌ Error: {str(e)}"
    # ... other counters omitted for brevity
    cursor.execute("SELECT COUNT(*) FROM ApproveKBArticle WHERE name = %s AND status = 'approved'", (session['cn'],))
    approveCount = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM ApproveKBArticle WHERE name = %s AND status = 'rejected'", (session['cn'],))
    rejectCount = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM ApproveKBArticle WHERE name = %s", (session['cn'],))
    totalCount = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM ApproveKBArticle WHERE name = %s AND status = 'Pending'", (session['cn'],))
    pendingCount = cursor.fetchone()[0]

    return render_template('grant_permissions.html',
        name=session['cn'],
        is_admin=True,
        is_kb_approver=session.get('is_kb_approver', False),
        approveCount=approveCount, rejectCount=rejectCount,
        totalCount=totalCount, pendingCount=pendingCount,
        message=message
    )

########################################### ROUTES FOR HOMEPAGE AND ARTICLE MANAGEMENT ##############################################

# Homepage
@app.route('/home')
def homepage():
    if 'cn' not in session:
        return redirect(url_for('login'))

    name = session['cn']
    username = session['username']
    is_admin = session.get('is_admin', False)

    # Check KBApprover flag
    cursor.execute("SELECT username FROM KBApprovers WHERE username = %s", (username,))
    is_kb_approver = cursor.fetchone() is not None
    session['is_kb_approver'] = is_kb_approver

    # Fetch all articles if admin or approver
    all_articles = []
    if is_admin or is_kb_approver:
        cursor.execute("SELECT * FROM ApproveKBArticle")
        all_articles = cursor.fetchall()
    
    # User article counts
    cursor.execute("SELECT COUNT(*) FROM ApproveKBArticle WHERE name = %s AND status = 'approved'", (name,))
    approveCount = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM ApproveKBArticle WHERE name = %s AND status = 'rejected'", (name,))
    rejectCount = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM ApproveKBArticle WHERE name = %s", (name,))
    totalCount = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM ApproveKBArticle WHERE name = %s AND status = 'Pending'", (name,))
    pendingCount = cursor.fetchone()[0]

    # ✅ Use DB groups (not AD) for graphs
    cursor.execute("SELECT group_name FROM groups_kbarticle ORDER BY group_name ASC")
    group_names = [row[0] for row in cursor.fetchall()]

    # ✅ Count articles per group (bar graph)
    group_counts = []
    for g in group_names:
        cursor.execute("SELECT COUNT(*) FROM ApproveKBArticle WHERE ADGroups = %s", (g,))
        group_counts.append(cursor.fetchone()[0])

    # ✅ Count articles per group member (pie/drilldown)
    group_members_data = {}
    for g in group_names:
        cursor.execute("""
            SELECT name, COUNT(*) 
            FROM ApproveKBArticle 
            WHERE ADGroups = %s 
            GROUP BY name
        """, (g,))
        group_members_data[g] = cursor.fetchall()  # [(username, count), ...]

    return render_template(
        'HomePage.html',
        name=name,
        is_admin=is_admin,
        is_kb_approver=is_kb_approver,
        records=all_articles,
        approveCount=approveCount,
        rejectCount=rejectCount,
        totalCount=totalCount,
        pendingCount=pendingCount,
        group_labels=group_names,
        group_counts=group_counts,
        group_members_data=group_members_data
    )

@app.route('/add_groups', methods=['GET', 'POST'])
def add_groups():
    if 'cn' not in session or not session.get('is_admin'):
        return redirect(url_for('login'))
    message = None
    cn_name = session['cn']
    if request.method == 'POST':
        action = request.form.get('action')
        group_name = request.form.get('groupname', '').strip()
        try:
            if action == 'add' and group_name:
                cursor.execute("INSERT IGNORE INTO groups_kbarticle (group_name) VALUES (%s)", (group_name,))
                if cursor.rowcount > 0:  # only inserted if new
                    db.commit()
                    message = f"✅ Group '{group_name}' added successfully!"
                else:
                    message = f"⚠️ Group '{group_name}' already exists!"
            elif action == 'remove' and group_name:
                cursor.execute("DELETE FROM groups_kbarticle WHERE group_name = %s", (group_name,))
                if cursor.rowcount > 0:
                    db.commit()
                    message = f"❌ Group '{group_name}' removed successfully!"
                else:
                    message = f"⚠️ Group '{group_name}' does not exist!"
        except Exception as e:
            db.rollback()
            message = f"❌ Error: {str(e)}"
    cursor.execute("SELECT group_name FROM groups_kbarticle ORDER BY group_name ASC")
    groups = [row[0] for row in cursor.fetchall()]

    cursor.execute("SELECT COUNT(*) FROM ApproveKBArticle WHERE name = %s AND status = 'approved'", (cn_name,))
    approveCount = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM ApproveKBArticle WHERE name = %s AND status = 'rejected'", (cn_name,))
    rejectCount = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM ApproveKBArticle WHERE name = %s", (cn_name,))
    totalCount = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM ApproveKBArticle WHERE name = %s AND status = 'Pending'", (cn_name,))
    pendingCount = cursor.fetchone()[0]

    return render_template('add_groups.html', 
                           name=session['cn'], 
                           is_admin=session.get('is_admin', False),
                           is_kb_approver=session.get('is_kb_approver', False),
                           groups=groups,
                           message=message, approveCount=approveCount, rejectCount=rejectCount,
                           totalCount=totalCount, pendingCount=pendingCount)

################################### ARTICLE MANAGEMENT ROUTES ###################################

# SUBMIT ARTICLE
@app.route('/submit', methods=['GET', 'POST'])
def submit():
    if 'cn' not in session:
        return redirect(url_for('login'))
    
    cn_name = session['cn']
    cursor.execute("SELECT group_name FROM groups_kbarticle ORDER BY group_name ASC")
    groups = [row[0] for row in cursor.fetchall()]
    print("Available groups for submission:", groups)
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
        prefix = group[:4].upper()
        cursor.execute("""
            SELECT COUNT(*) FROM ApproveKBArticle WHERE ADGroups LIKE %s
        """, (f'%{group}%',))
        count = cursor.fetchone()[0] + 1
        article_id = f"{prefix}-{count:03d}"


        sql = "INSERT INTO ApproveKBArticle (name, title, description, url, filename, ADGroups, article_id_custom) VALUES (%s, %s, %s, %s, %s, %s, %s)"
        val = (name, title, description, url, filename, group, article_id)
        cursor.execute(sql, val)
        db.commit()

        '''try:
            msg = EmailMessage()
            TO = ["test1@freesmtpservers.com"]
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
            print("❌ Error sending email:", str(e))'''
        
        flash(f"✅ Article submitted successfully! Article ID: {article_id}", "success")
        return redirect(url_for('submit'))
    
    cursor.execute("SELECT COUNT(*) FROM ApproveKBArticle WHERE name = %s AND status = 'approved'", (cn_name,))
    approveCount = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM ApproveKBArticle WHERE name = %s AND status = 'rejected'", (cn_name,))
    rejectCount = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM ApproveKBArticle WHERE name = %s", (cn_name,))
    totalCount = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM ApproveKBArticle WHERE name = %s AND status = 'Pending'", (cn_name,))
    pendingCount = cursor.fetchone()[0]

    return render_template('form.html', name=cn_name, groups=groups, is_admin=session.get('is_admin', False), is_kb_approver=session.get('is_kb_approver', False),
    approveCount=approveCount,
    rejectCount=rejectCount,
    totalCount=totalCount,
    pendingCount=pendingCount)

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
                           is_admin=session.get('is_admin', False), 
                           is_kb_approver=session.get('is_kb_approver', False), 
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
                           is_admin=session.get('is_admin', False), 
                           is_kb_approver=session.get('is_kb_approver', False), 
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
                           is_admin=session.get('is_admin', False), 
                           is_kb_approver=session.get('is_kb_approver', False), 
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

    return render_template('pending.html', records=records, name=cn_name, 
                           is_admin=session.get('is_admin', False), 
                           is_kb_approver=session.get('is_kb_approver', False),
                           approveCount=approveCount, rejectCount=rejectCount, 
                           totalCount=totalCount, pendingCount=pendingCount)

@app.route('/edit/<int:article_id>', methods=['GET', 'POST'])
def edit_article(article_id):
    if 'cn' not in session:
        return redirect(url_for('login'))

    cursor.execute("SELECT * FROM ApproveKBArticle WHERE id = %s", (article_id,))
    article = cursor.fetchone()

    if not article or article[6] != 'rejected':
        return redirect(url_for('my_articles'))

    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        url = request.form['url']
        file = request.files['file']

        filename = article[5]  # Keep old filename by default
        if file and file.filename != '':
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)

        cursor.execute("""
            UPDATE ApproveKBArticle 
            SET title = %s, description = %s, url = %s, filename = %s, status = 'Pending', rejection_comment = NULL
            WHERE id = %s
        """, (title, description, url, filename, article_id))
        db.commit()
        flash("✅ Article Updated Successfully!", "success")
        return redirect(url_for('pending_articles'))

    return render_template('edit_modal_content.html', article=article)


# SEARCH ARTICLES
def search_articles(query):
    cursor.execute("""
        SELECT id, title, description, article_id_custom
        FROM ApproveKBArticle
        WHERE status = 'approved'
        AND (
            MATCH(title, description) AGAINST (%s IN NATURAL LANGUAGE MODE)
            OR article_id_custom LIKE %s
        )
        ORDER BY
            CASE
                WHEN article_id_custom LIKE %s THEN 1
                ELSE 0
            END DESC,
            MATCH(title, description) AGAINST (%s IN NATURAL LANGUAGE MODE) DESC
        LIMIT 20
    """, (query, f"%{query}%", f"%{query}%", query))
    
    results = cursor.fetchall()
    return [{'id': row[0], 'title': row[1], 'article_id_custom': row[3]} for row in results]

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
    cn_name = session.get('cn', None)
    if not cn_name:
        return redirect(url_for('login'))
    if 'cn' not in session:
        return redirect(url_for('login'))

    cursor.execute("SELECT * FROM ApproveKBArticle WHERE id = %s", (article_id,))
    article = cursor.fetchone()

    if not article:
        return redirect(url_for('my_articles')) 
    cursor.execute("SELECT COUNT(*) FROM ApproveKBArticle WHERE name = %s AND status = 'approved'", (cn_name,))
    approveCount = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM ApproveKBArticle WHERE name = %s AND status = 'rejected'", (cn_name,))
    rejectCount = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM ApproveKBArticle WHERE name = %s", (cn_name,))
    totalCount = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM ApproveKBArticle WHERE name = %s AND status = 'Pending'", (cn_name,))
    pendingCount = cursor.fetchone()[0]
    # Render the edit form with the article data
    return render_template('view_myarticle.html', article=article, name=cn_name, 
                           is_admin=session.get('is_admin', False), 
                           is_kb_approver=session.get('is_kb_approver', False),
                           approveCount=approveCount, rejectCount=rejectCount, 
                           totalCount=totalCount, pendingCount=pendingCount)

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