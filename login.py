from flask import Flask, render_template, request, jsonify
from ldap3 import Server, Connection, ALL, NTLM

app = Flask(__name__)

# Active Directory Configuration
AD_SERVER = 'ldap://172.26.249.33'  # Replace with your AD server
AD_DOMAIN = 'test11.com'  # Replace with your domain
AD_TIMEOUT = 5  # Timeout in seconds

@app.route('/')
def login_page():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    # Connect to Active Directory
    try:
        server = Server(AD_SERVER, get_info=ALL, connect_timeout=AD_TIMEOUT)
        user_dn = f"{AD_DOMAIN}\\{username}"
        conn = Connection(server, user=user_dn, password=password, authentication=NTLM)

        if conn.bind():
            conn.unbind()
            return "Login Successful! User authenticated."
        else:
            return "User not found or invalid credentials. Please check your credentials."
    except Exception as e:  # Use generic Exception
        return f"An error occurred: {str(e)}"

@app.route('/verify-ad')
def verify_ad():
    test_username = 'abcd1'  # Replace with a valid test username
    test_password = 'xxxxxx'  # Replace with the corresponding password

    try:
        server = Server(AD_SERVER, get_info=ALL, connect_timeout=AD_TIMEOUT)
        user_dn = f"{AD_DOMAIN}\\{test_username}"
        conn = Connection(server, user=user_dn, password=test_password, authentication=NTLM)

        if conn.bind():
            conn.unbind()
            return "Connection to Active Directory verified successfully!"
        else:
            return "Failed to connect to Active Directory. Check the test credentials."
    except Exception as e:  # Use generic Exception
        return f"An error occurred while verifying AD connection: {str(e)}"

if __name__ == '__main__':
    app.run(debug=True)