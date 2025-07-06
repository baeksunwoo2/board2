import os
import uuid
import bcrypt
import secrets
import datetime
from flask import (Flask, flash, redirect, render_template, request, session,
                   url_for, send_from_directory, Response)
from werkzeug.utils import secure_filename
from db_config import get_db_connection

app = Flask(__name__)
app.secret_key = 'your_very_secret_key'

UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)


def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def check_password(password, hashed):
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))


@app.route('/')
def index():
    search_query = request.args.get('q', '')
    search_type = request.args.get('type', 'title_content')
    conn = get_db_connection()
    cursor = conn.cursor()
    sql = "SELECT id, title, username, created_at, views, is_secret, user_id FROM posts "
    params = []
    if search_query:
        if search_type == 'title_content':
            sql += "WHERE title LIKE %s OR content LIKE %s "
            params.extend([f"%{search_query}%", f"%{search_query}%"])
        elif search_type == 'title':
            sql += "WHERE title LIKE %s "
            params.append(f"%{search_query}%")
        elif search_type == 'content':
            sql += "WHERE content LIKE %s "
            params.append(f"%{search_query}%")
        elif search_type == 'username':
            sql += "WHERE username LIKE %s "
            params.append(f"%{search_query}%")
    sql += "ORDER BY created_at DESC"
    cursor.execute(sql, tuple(params))
    posts = cursor.fetchall()
    conn.close()
    return render_template('index.html', posts=posts, search_query=search_query, search_type=search_type)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        real_name = request.form['real_name']
        school = request.form['school']
        age = request.form['age']

        hashed_password = hash_password(password)
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute(
                "INSERT INTO users (username, password, email, real_name, school, age) VALUES (%s, %s, %s, %s, %s, %s)",
                (username, hashed_password, email, real_name, school, age)
            )
            conn.commit()
            flash('회원가입이 완료되었습니다. 로그인해주세요.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            flash('이미 존재하는 사용자 이름 또는 이메일입니다.', 'danger')
        finally:
            conn.close()
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, password FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()
        conn.close()
        if user and check_password(password, user['password']):
            session['user_id'] = user['id']
            session['username'] = user['username']
            flash(f"{user['username']}님, 환영합니다!", 'success')
            return redirect(url_for('index'))
        else:
            flash('사용자 이름 또는 비밀번호가 올바르지 않습니다.', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('로그아웃되었습니다.', 'info')
    return redirect(url_for('index'))

@app.route('/find_id', methods=['GET', 'POST'])
def find_id():
    if request.method == 'POST':
        email = request.form['email']
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT username FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        conn.close()
        if user:
            flash(f"회원님의 아이디는 [ {user['username']} ] 입니다.", 'success')
        else:
            flash('해당 이메일로 가입된 아이디가 없습니다.', 'warning')
        return redirect(url_for('find_id'))
    return render_template('find_id.html')

@app.route('/find_password', methods=['GET', 'POST'])
def find_password():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE username = %s AND email = %s", (username, email))
        user = cursor.fetchone()
        if user:
            token = secrets.token_urlsafe(16)
            user_id = user['id']
            cursor.execute("INSERT INTO password_resets (user_id, token) VALUES (%s, %s)", (user_id, token))
            conn.commit()
            conn.close()
            
            reset_link = url_for('reset_password', token=token, _external=True)
            flash('비밀번호 재설정 링크가 생성되었습니다. 아래 링크로 접속하여 비밀번호를 재설정하세요.', 'info')
            flash(reset_link, 'link')
        else:
            conn.close()
            flash('입력하신 정보와 일치하는 사용자가 없습니다.', 'warning')
        return redirect(url_for('find_password'))
    return render_template('find_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    one_hour_ago = datetime.datetime.now() - datetime.timedelta(hours=1)
    cursor.execute("SELECT user_id FROM password_resets WHERE token = %s AND created_at >= %s", (token, one_hour_ago))
    reset_request = cursor.fetchone()

    if not reset_request:
        conn.close()
        flash('유효하지 않거나 만료된 토큰입니다.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        new_password = request.form['new_password']
        hashed_password = hash_password(new_password)
        user_id = reset_request['user_id']
        
        cursor.execute("UPDATE users SET password = %s WHERE id = %s", (hashed_password, user_id))
        cursor.execute("DELETE FROM password_resets WHERE token = %s", (token,))
        
        conn.commit()
        conn.close()
        
        flash('비밀번호가 성공적으로 재설정되었습니다. 다시 로그인해주세요.', 'success')
        return redirect(url_for('login'))

    conn.close()
    return render_template('reset_password.html', token=token)

@app.route('/profile')
def profile():
    if 'user_id' not in session:
        flash('로그인이 필요합니다.', 'danger')
        return redirect(url_for('login'))

    user_id = session['user_id']
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, email, real_name, school, age FROM users WHERE id = %s", (user_id,))
    user_info = cursor.fetchone()
    conn.close()

    if not user_info:
        flash('사용자 정보를 찾을 수 없습니다.', 'danger')
        return redirect(url_for('index'))

    return render_template('profile.html', user=user_info)

@app.route('/edit_profile', methods=['GET', 'POST'])
def edit_profile():
    if 'user_id' not in session:
        flash('로그인이 필요합니다.', 'danger')
        return redirect(url_for('login'))

    user_id = session['user_id']
    conn = get_db_connection()
    cursor = conn.cursor()

    if request.method == 'POST':
        real_name = request.form['real_name']
        school = request.form['school']
        age = request.form['age']

        if 'profile_image' in request.files:
            file = request.files['profile_image']
            if file.filename != '':
                image_data = file.read()
                cursor.execute(
                    "UPDATE users SET real_name = %s, school = %s, age = %s, profile_image = %s WHERE id = %s",
                    (real_name, school, age, image_data, user_id)
                )
            else:
                cursor.execute(
                    "UPDATE users SET real_name = %s, school = %s, age = %s WHERE id = %s",
                    (real_name, school, age, user_id)
                )
        
        conn.commit()
        conn.close()
        flash('프로필이 성공적으로 수정되었습니다.', 'success')
        return redirect(url_for('profile'))

    cursor.execute("SELECT id, real_name, school, age FROM users WHERE id = %s", (user_id,))
    user_info = cursor.fetchone()
    conn.close()
    return render_template('edit_profile.html', user=user_info)

@app.route('/search_users', methods=['GET'])
def search_users():
    query = request.args.get('query', '')
    users = []
    if query:
        conn = get_db_connection()
        cursor = conn.cursor()
        search_pattern = f"%{query}%"
        cursor.execute(
            "SELECT id, username, real_name, school FROM users WHERE real_name LIKE %s OR school LIKE %s",
            (search_pattern, search_pattern)
        )
        users = cursor.fetchall()
        conn.close()
    
    return render_template('search_users.html', users=users, query=query)

@app.route('/user_profile/<username>')
def user_profile(username):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, real_name, school, age FROM users WHERE username = %s", (username,))
    user_info = cursor.fetchone()
    conn.close()

    if not user_info:
        flash('존재하지 않는 사용자입니다.', 'danger')
        return redirect(url_for('index'))

    return render_template('user_profile.html', user=user_info)

@app.route('/user_avatar/<int:user_id>')
def get_user_avatar(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT profile_image FROM users WHERE id = %s", (user_id,))
    user = cursor.fetchone()
    conn.close()

    if user and user['profile_image']:
        return Response(user['profile_image'], mimetype='image/jpeg')
    else:
        try:
            with open(os.path.join(app.root_path, 'static/images/default_avatar.png'), 'rb') as f:
                return Response(f.read(), mimetype='image/png')
        except FileNotFoundError:
            return 'No Image', 404

@app.route('/write', methods=['GET', 'POST'])
def write():
    if 'user_id' not in session:
        flash('로그인이 필요합니다.', 'danger')
        return redirect(url_for('login'))
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        user_id = session['user_id']
        username = session['username']
        is_secret = 1 if 'is_secret' in request.form else 0
        filename = None
        stored_filename = None
        if 'file' in request.files:
            file = request.files['file']
            if file.filename != '':
                filename = secure_filename(file.filename)
                extension = filename.split('.')[-1]
                stored_filename = f"{uuid.uuid4()}.{extension}"
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], stored_filename))
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO posts (title, content, user_id, username, is_secret, filename, stored_filename) VALUES (%s, %s, %s, %s, %s, %s, %s)",
            (title, content, user_id, username, is_secret, filename, stored_filename)
        )
        conn.commit()
        conn.close()
        flash('게시글이 성공적으로 작성되었습니다.', 'success')
        return redirect(url_for('index'))
    return render_template('write.html')

@app.route('/post/<int:post_id>')
def view(post_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE posts SET views = views + 1 WHERE id = %s", (post_id,))
    conn.commit()
    cursor.execute("SELECT * FROM posts WHERE id = %s", (post_id,))
    post = cursor.fetchone()
    if post is None:
        conn.close()
        flash('존재하지 않는 게시글입니다.', 'danger')
        return redirect(url_for('index'))
    if post['is_secret']:
        if 'user_id' not in session or session['user_id'] != post['user_id']:
            conn.close()
            flash('비밀글은 작성자만 조회할 수 있습니다.', 'warning')
            return redirect(url_for('index'))
    conn.close()
    return render_template('view.html', post=post)

@app.route('/edit/<int:post_id>', methods=['GET', 'POST'])
def edit(post_id):
    if 'user_id' not in session:
        flash('로그인이 필요합니다.', 'danger')
        return redirect(url_for('login'))
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM posts WHERE id = %s", (post_id,))
    post = cursor.fetchone()
    if post['user_id'] != session['user_id']:
        conn.close()
        flash('수정 권한이 없습니다.', 'danger')
        return redirect(url_for('index'))
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        is_secret = 1 if 'is_secret' in request.form else 0
        filename = post['filename']
        stored_filename = post['stored_filename']
        if 'file' in request.files:
            file = request.files['file']
            if file.filename != '':
                if stored_filename:
                    os.remove(os.path.join(app.config['UPLOAD_FOLDER'], stored_filename))
                filename = secure_filename(file.filename)
                extension = filename.split('.')[-1]
                stored_filename = f"{uuid.uuid4()}.{extension}"
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], stored_filename))
        cursor.execute(
            "UPDATE posts SET title = %s, content = %s, is_secret = %s, filename = %s, stored_filename = %s WHERE id = %s",
            (title, content, is_secret, filename, stored_filename, post_id)
        )
        conn.commit()
        conn.close()
        flash('게시글이 수정되었습니다.', 'success')
        return redirect(url_for('view', post_id=post_id))
    conn.close()
    return render_template('edit.html', post=post)

@app.route('/delete/<int:post_id>', methods=['POST'])
def delete(post_id):
    if 'user_id' not in session:
        flash('로그인이 필요합니다.', 'danger')
        return redirect(url_for('login'))
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT user_id, stored_filename FROM posts WHERE id = %s", (post_id,))
    post = cursor.fetchone()
    if post and post['user_id'] == session['user_id']:
        cursor.execute("DELETE FROM posts WHERE id = %s", (post_id,))
        conn.commit()
        if post['stored_filename']:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], post['stored_filename'])
            if os.path.exists(file_path):
                os.remove(file_path)
        flash('게시글이 삭제되었습니다.', 'success')
    else:
        flash('삭제 권한이 없거나 존재하지 않는 게시글입니다.', 'danger')
    conn.close()
    return redirect(url_for('index'))

@app.route('/withdraw', methods=['POST'])
def withdraw():
    if 'user_id' not in session:
        flash('로그인이 필요합니다.', 'danger')
        return redirect(url_for('login'))
    user_id = session['user_id']
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
    conn.commit()
    conn.close()
    session.clear()
    flash('회원탈퇴가 완료되었습니다. 이용해주셔서 감사합니다.', 'success')
    return redirect(url_for('index'))

@app.route('/download/<int:post_id>')
def download(post_id):
    if 'user_id' not in session:
        flash('로그인이 필요합니다.', 'danger')
        return redirect(url_for('login'))
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM posts WHERE id = %s", (post_id,))
    post = cursor.fetchone()
    conn.close()
    if not post or not post['stored_filename']:
        flash('파일이 존재하지 않습니다.', 'danger')
        return redirect(url_for('view', post_id=post_id))
    if post['is_secret'] and session['user_id'] != post['user_id']:
        flash('파일 다운로드 권한이 없습니다.', 'warning')
        return redirect(url_for('index'))
    return send_from_directory(app.config['UPLOAD_FOLDER'], post['stored_filename'], as_attachment=True, download_name=post['filename'])


# --- 앱 실행 ---
if __name__ == '__main__':
    app.run(debug=True, port=5001)

