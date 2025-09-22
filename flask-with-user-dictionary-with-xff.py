import os
from datetime import timedelta
import time, logging
from flask import Flask, send_from_directory, render_template, session, request, redirect, url_for, flash, abort
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'  # Replace with a secure key or use environment variable
app.permanent_session_lifetime = timedelta(minutes=30)

# Optional IP filtering (disabled by default)
# TRUSTED_PROXIES = ['your.proxy.ip']
# ALLOWED_CLIENTS = ['your.client.ip']

TRUSTED_PROXIES = ['10.0.0.0/24', '*']
ALLOWED_CLIENTS = ['10.0.0.0/24', '*']

app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

# 🔐 Dictionary of users with password and folder mapping
USER_CREDENTIALS = {
    'bbteam': {'password': 'your-password-here', 'folder': r'/path/to/bbteam'},
    'l3team': {'password': 'your-password-here', 'folder': r'/path/to/l3team'},
    'l2team': {'password': 'your-password-here', 'folder': r'/path/to/l2team'},
    'pmsteam': {'password': 'your-password-here', 'folder': r'/path/to/pmsteam'},
    'itteam': {'password': 'your-password-here', 'folder': r'/path/to/itteam'},
    'nmsteam': {'password': 'your-password-here', 'folder': r'/path/to/nmsteam'},
    'sftpuser': {'password': 'your-password-here', 'folder': r'/path/to/sftpuser/accepted'}
}

logging.basicConfig(
    filename='access.log',
    level=logging.INFO,
    format='%(asctime)s %(levelname)s: %(message)s'
)

def get_verified_client_ip(headers, remote_ip):
    xff = headers.get('X-Forwarded-For')
    if remote_ip in TRUSTED_PROXIES and xff:
        return xff.split(',')[0].strip()
    return remote_ip

def log_request_header():
    for header, value in request.headers.items():
        try:
            print(f"[HEADER]{header}:{value}")
        except Exception as e:
            print(f"[HEADER ERROR]{header}:{e}")

'''
@app.before_request
def enforce_ip_whitelist():
    log_request_header()
    client_ip = get_verified_client_ip(request.headers, request.remote_addr)
    xff = request.headers.get('X-Forwarded-For')

    print(f"[DEBUG] X-Forwarded-For header received: {xff}")
    print(f"[DEBUG] Remote IP: {request.remote_addr}")
    print(f"[DEBUG] Parsed Client IP: {client_ip}")
    log_entry = f"Access attempt from {client_ip} via proxy {request.remote_addr}"
    if client_ip not in ALLOWED_CLIENTS:
        logging.warning(f"{log_entry} - BLOCKED")
        abort(403)
    else:
        logging.info(f"{log_entry} - ALLOWED")
'''

# 🔐 Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, username):
        self.id = username
        self.username = username

@login_manager.user_loader
def load_user(user_id):
    if user_id in USER_CREDENTIALS:
        return User(user_id)
    return None

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user_data = USER_CREDENTIALS.get(username)

        if not user_data or user_data['password'] != password:
            flash("Invalid username or password")
            return redirect(url_for('login'))

        session.permanent = True
        login_user(User(username))
        session['folder'] = user_data['folder']
        return redirect(url_for('files'))

    return render_template('login.html')

def get_files():
    user_folder = session.get('folder')
    if user_folder and os.path.exists(user_folder):
        return os.listdir(user_folder)
    return []

@app.route('/files')
@login_required
def files():
    user_folder = session.get('folder')
    if not user_folder or not os.path.exists(user_folder):
        flash("Folder not found.")
        return redirect(url_for('login'))

    try:
        file_list = os.listdir(user_folder)
    except Exception as e:
        flash(f"Error accessing folder: {str(e)}")
        file_list = []

    file_mtimes = {
        file: os.path.getmtime(os.path.join(user_folder, file))
        for file in file_list
    }

    sorted_files = sorted(file_mtimes.items(), key=lambda x: x[1], reverse=True)

    file_dates = {
        f: time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(os.path.getmtime(os.path.join(user_folder, f))))
        for f in file_list
    }

    sorted_file_list = [file for file, _ in sorted_files]
    return render_template('files.html', files=sorted_file_list, current_user=current_user, file_dates=file_dates)

@app.route('/search')
@login_required
def search():
    query = request.args.get('query', '').lower()
    all_files = get_files()
    filtered_files = [f for f in all_files if query in f.lower()]
    user_folder = session.get('folder')

    file_mtimes = {
        f: os.path.getmtime(os.path.join(user_folder, f))
        for f in filtered_files
    }

    sorted_files = sorted(file_mtimes.items(), key=lambda x: x[1], reverse=True)
    sorted_files_list = [file for file, _ in sorted_files]

    file_dates = {
        f: time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(os.path.getmtime(os.path.join(user_folder, f))))
        for f in filtered_files
    }

    return render_template('files.html', files=sorted_files_list, current_user=current_user, file_dates=file_dates)

@app.route('/download/<filename>')
@login_required
def download(filename):
    user_folder = session.get('folder')
    if not user_folder or filename not in os.listdir(user_folder):
        return "File not found", 404
    return send_from_directory(user_folder, filename, as_attachment=True)

@app.route('/delete', methods=['POST'])
@login_required
def delete_file():
    filename = request.form.get('filepath')
    user_folder = session.get('folder')
    safe_root = os.path.abspath(user_folder)
    full_path = os.path.abspath(os.path.join(safe_root, filename))

    if not full_path.startswith(safe_root):
        flash("Invalid file path.")
        return redirect(url_for('files'))

    try:
        os.remove(full_path)
        flash(f"Deleted: {filename}")
    except Exception as e:
        flash(f"Error deleting file: {str(e)}")

    return redirect(url_for('files'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(ssl_context=('cert.pem', 'key.pem'), host='0.0.0.0', port=443)