import smtplib
from typing import cast
from sqlalchemy import Integer, String, Text, Boolean, or_
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SubmitField, PasswordField, EmailField
from wtforms.fields.simple import BooleanField
from wtforms.validators import DataRequired, Email, Length, Regexp, ValidationError
from flask_ckeditor import CKEditorField,CKEditor
import bleach
from datetime import datetime
from flask import Flask, render_template, request, url_for, redirect, flash,  jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, joinedload, QueryableAttribute
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user
import os
from dotenv import load_dotenv
from flask_login import current_user

load_dotenv()
admins = set(os.getenv("ADMINS", "{}").replace("{", "").replace("}", "").replace('"', '').split(","))
admins = {email.strip().lower() for email in admins}
super_admin = os.getenv('SUPERADMIN')

def no_whitespace(form, field):
    if " " in field.data:
        raise ValidationError("No spaces allowed in the username.")

class ContactForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired(message="Please enter your name.")])
    email = StringField("Email", validators=[DataRequired(message="Please enter your email."), Email()])
    phone = StringField("Phone Number")  # Optional field
    message = TextAreaField("Message", validators=[DataRequired(message="Please enter your message.")])
    submit = SubmitField("Submit")

class Base(DeclarativeBase):
    pass

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv('SECRET')

# Environment-based database configuration:
if os.getenv("FLASK_ENV") == "production":
    # Production configuration: Use your production database URI (e.g., PostgreSQL)
    app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("PROD_DATABASE_URI")


# Optional, but recommended
else:
    # Local development: Use a SQLite database+
    app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("SQLITE_URL", "sqlite:///local_new.db")

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config['CKEDITOR_PKG_TYPE'] = 'full'
app.config['CKEDITOR_SERVE_LOCAL'] = True
app.config['CKEDITOR_HEIGHT'] = 200
ckeditor = CKEditor(app)
db = SQLAlchemy(model_class=Base)
db.init_app(app)

login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)


class NewPostForm(FlaskForm):
    title = StringField("Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    author = StringField("Author")
    img_url = StringField("Background Image URL", validators=[DataRequired()])
    body = CKEditorField('Body')
    visibility = BooleanField("Visibility", default=False)
    submit = SubmitField("Submit Post")


class RegisterForm(FlaskForm):
    name = StringField("Name", validators=[
        DataRequired(),
        Length(min=3, max=15, message="Username should have a length of 3-9."),
        no_whitespace
    ])
    email = EmailField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[
        DataRequired(),
        Length(min=8, message="Password must be at least 8 characters long."),
        Regexp(r'^(?=.*[A-Z]).+$', message="Password must contain at least one uppercase letter.")
    ])
    submit = SubmitField("Sign Me Up")

class LoginForm(FlaskForm):
    email_or_name = StringField("Name", validators=[DataRequired()])
    password = PasswordField("Password", validators=[
        DataRequired(),
        Length(min=8, message="Password must be at least 8 characters long."),
        Regexp(r'^(?=.*[A-Z]).+$', message="Password must contain at least one uppercase letter.")
    ])
    submit = SubmitField("Let Me In")

class CommentForm(FlaskForm):
    comment = CKEditorField('Comment')
    submit = SubmitField('Post Comment')

class AdminForm(FlaskForm):
    email = EmailField("Email", validators=[DataRequired()])
    add_button = SubmitField("ADD")
    del_button = SubmitField("DELETE")

class ChangePasswordForm(FlaskForm):
    old_password = PasswordField("Password", validators=[DataRequired()])
    new_password = PasswordField("Password", validators=[
        DataRequired(),
        Length(min=8, message="Password must be at least 8 characters long."),
        Regexp(r'^(?=.*[A-Z]).+$', message="Password must contain at least one uppercase letter.")
    ])
    submit = SubmitField("Change Password")

class BlogPost(db.Model):
    __tablename__ = "blog_post"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    subtitle: Mapped[str] = mapped_column(String(250), nullable=False)
    date: Mapped[str] = mapped_column(String(250), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    author: Mapped[str] = mapped_column(String(250), nullable=False)
    img_url: Mapped[str] = mapped_column(String(250), nullable=False)
    visibility: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    user_id: Mapped[int] = mapped_column(Integer, db.ForeignKey("user.id"), nullable=False)

    user = db.relationship("User", back_populates="posts")
    comments = db.relationship("Comment", back_populates="post", cascade="all, delete-orphan")


class User(db.Model, UserMixin):
    __tablename__ = "user"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(100), unique=True)
    password: Mapped[str] = mapped_column(String(100))
    name: Mapped[str] = mapped_column(String(1000), unique=True)
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False)

    posts = db.relationship("BlogPost", back_populates="user", cascade="all, delete-orphan")
    comments = db.relationship("Comment", back_populates="user", cascade="all, delete-orphan")

    def __init__(self, name, email, password, is_admin):
        self.name = name
        self.email = email
        self.password = password
        self.is_admin = is_admin

class Comment(db.Model):
    __tablename__ = "comments"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    text: Mapped[str] = mapped_column(Text, nullable=False)
    date: Mapped[str] = mapped_column(String(250), nullable=False)
    user_id: Mapped[int] = mapped_column(Integer, db.ForeignKey("user.id"), nullable=False)
    post_id: Mapped[int] = mapped_column(Integer, db.ForeignKey("blog_post.id"), nullable=False)

    user = db.relationship("User", back_populates="comments")
    post = db.relationship("BlogPost", back_populates="comments")

class Admin(db.Model):
    __table__name = "admins"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)

# with app.app_context():
#     db.create_all()

my_email = os.getenv("EMAIL")  # your email
my_email_password = os.getenv("EMAIL_PASSWORD")


def get_blog_posts():
    with app.app_context():
        posts = BlogPost.query.options(joinedload(cast(QueryableAttribute, BlogPost.user))).all()
        return posts


def get_users_blog_posts():
    with app.app_context():
        if current_user.is_authenticated and current_user.is_admin:
            return get_blog_posts()  # Admin sees all posts
        elif current_user.is_authenticated:
            return BlogPost.query.options(joinedload(cast(QueryableAttribute, BlogPost.user))).where(BlogPost.user_id == current_user.id).all()

def send_email(message):
    with smtplib.SMTP("smtp.gmail.com") as connection:
        connection.starttls()
        connection.login(user=my_email, password=my_email_password)
        connection.sendmail(from_addr=my_email, to_addrs=my_email, msg=message)

def get_date():
    monthsList = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November",
                  "December"]
    today = datetime.today().date()
    return f"{monthsList[today.month - 1]} {today.day}, {today.year}"

def super_admin_only(function):
    def wrapper(*args, **kwargs):
        if current_user.is_authenticated and current_user.email == super_admin:
            return function(*args, **kwargs)
        else:
            flash("Access denied! Only the Super Admin can perform this action.", "danger")
            return redirect(url_for('home'))
    wrapper.__name__ = function.__name__
    return wrapper

def hash_password(password):
    hashed_pass = generate_password_hash(
        password=password,
        method="pbkdf2:sha256:600000",
        salt_length=8
    )
    return hashed_pass

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

@app.route('/home')
@login_required
def home():
    posts = get_users_blog_posts()
    return render_template("home.html", posts=posts)

@app.route('/')
def root():
    posts = get_blog_posts()
    return render_template("root.html", posts=posts)


@app.route('/post/<int:post_id>', methods=['GET', 'POST'])
def blog(post_id):
    post = BlogPost.query.options(joinedload(cast(QueryableAttribute, BlogPost.user))).where(
        BlogPost.id == post_id).scalar()

    form = CommentForm()

    if form.validate_on_submit():
        new_comment = Comment(
            text=form.comment.data,
            date=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            user_id=current_user.id,
            post_id=post_id
        )
        db.session.add(new_comment)
        db.session.commit()
        flash("Your comment has been added!", "success")
        return redirect(url_for('blog', post_id=post_id))

    return render_template('post.html', blog_post=post, form=form)


@app.route("/contact", methods=["GET", "POST"])
def contact():
    form = ContactForm()
    if form.validate_on_submit():
        msg = (
            f"Subject: Contacted from BLOG Server\n\n"
            f"Name: {form.name.data}\n"
            f"Email: {form.email.data}\n"
            f"Phone: {form.phone.data or 'N/A'}\n"
            f"Message: {form.message.data}\n"
        )
        send_email(msg)
        flash("Your message has been sent successfully.", "success")
        return render_template("contact.html", form=form, msg_sent=True)
    return render_template("contact.html", form=form, msg_sent=False)

@app.route('/about')
def about():
    return render_template('about.html')


@app.route('/new-post', methods=["POST", "GET"])
@login_required
def make_post():
    form = NewPostForm()
    if request.method == "POST" and form.validate_on_submit():
        clean_body = bleach.clean(form.body.data,
                                  tags=['p', 'b', 'i', 'em', 'strong', 'u', 'a', 'ul', 'ol', 'li', 'br'],
                                  attributes={'a': ['href', 'title']}, strip=True)
        new_post = BlogPost(
            title=form.title.data,
            body=clean_body,
            subtitle=form.subtitle.data,
            img_url=form.img_url.data,
            author=form.author.data or current_user.name,
            date=get_date(),
            user_id= current_user.id,
            visibility=not form.visibility.data
        )
        db.session.add(new_post)
        db.session.commit()
        flash('Post created successfully!', 'success')
        return redirect(url_for('home'))
    return render_template("make-post.html", form=form)

@app.route("/delete-post", methods=["GET"])
@login_required
def delete():
    post_id = request.args.get("post_id")
    post = db.session.execute(db.select(BlogPost).where(BlogPost.id == post_id)).scalar()
    db.session.delete(post)
    db.session.commit()
    return redirect(url_for('home'))

@app.route('/edit-post/<int:post_id>', methods=["GET", "POST"])
@login_required
def edit(post_id):
    post = BlogPost.query.get_or_404(post_id)  # Fetch the post from the database
    form = NewPostForm(obj=post)  # Prepopulate form with post data
    if request.method == "GET":
        form.visibility.data = not post.visibility
    if form.validate_on_submit():
        post.title = form.title.data
        post.subtitle = form.subtitle.data
        post.author = form.author.data
        post.img_url = form.img_url.data
        post.body = form.body.data
        post.visibility = not form.visibility.data
        post.date = get_date()
        db.session.commit()
        flash("Post updated successfully!", "success")
        return redirect( url_for('blog', post_id=post.id) )

    return render_template("edit-post.html", form=form)

# Authentication
@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if request.method == "POST" and form.validate_on_submit():
        user = ( db.session.execute(db.select(User).where(User.email == form.email_or_name.data.lower())).scalar_one_or_none() or
            db.session.execute(db.select(User).where(User.name == form.email_or_name.data)).scalar_one_or_none() )

        if user and check_password_hash(user.password, form.password.data):
            login_user(user, remember=True)
            return redirect(url_for('home'))
        else:
            flash('Invalid Username or Email or password. Please try again.', 'danger')
    return render_template('login.html', form=form)

@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if request.method == "POST" and form.validate_on_submit():
        user_email = form.email.data.strip().lower()
        if db.session.execute(db.select(User).where(User.email == user_email)).scalar_one_or_none():
            flash('Email already exists. Please log in.', 'warning')
            return redirect(url_for('login'))
        admin_in_env = user_email in admins
        admin_in_db = Admin.query.filter_by(email=user_email).first() is not None
        hashed_and_salted_password = hash_password(form.password.data)
        new_user = User(
            name=form.name.data,
            email=user_email.lower(),
            password=hashed_and_salted_password,
            is_admin=admin_in_db or admin_in_env
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user, remember=True)
        return redirect(url_for('home'))
    return render_template("register.html", form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('root'))

# you can use this endpoint to search for a particular post eg /search?q=
@app.route('/search')
def search():
    query = request.args.get('q', '')
    app.logger.info("Search query received: %s", query)

    if query:
        results = BlogPost.query.outerjoin(BlogPost.user).filter(
            BlogPost.visibility == True,
            or_(
                BlogPost.title.ilike(f'%{query}%'),
                BlogPost.author.ilike(f'%{query}%'),
                User.name.ilike(f'%{query}%')  # Changed from username to name
            )
        ).limit(5).all()
    else:
        results = []
    results_list = []
    for post in results:
        author_display = post.author if post.author else (post.user.name if post.user else 'Unknown')
        results_list.append({
            'id': post.id,
            'title': post.title,
            'author': author_display,
            'url': url_for('blog', post_id=post.id)  # Ensure this endpoint exists.
        })
    return jsonify(results_list)

@app.route('/admin-changes', methods=["GET", "POST"])
@login_required
@super_admin_only
def add_or_del_admins():
    form = AdminForm()
    print("working")
    if request.method == "POST" and form.validate_on_submit():

        email = form.email.data.strip().lower()
        admin_in_env = email in admins
        admin_in_db = Admin.query.filter_by(email=email).first() is not None
        msg = ''

        if form.add_button.data:
            if admin_in_env or admin_in_db:
                msg = "User is already an admin."
            else:
                new_admin = Admin(email=email)
                db.session.add(new_admin)
                db.session.commit()
                msg = f"User {email} is added as an admin."

        elif form.del_button.data:
            if admin_in_env:
                msg = "Cannot remove an admin from the .env file!"
            elif admin_in_db:
                admin_entry = Admin.query.filter_by(email=email).first()
                db.session.delete(admin_entry)
                admin_user = db.session.execute(db.select(User).where(User.email == email)).scalar()
                admin_user.is_admin = False
                db.session.commit()
                msg = f"User {email} has been removed from admin list."
            else:
                msg = "User is not an admin."

        home_url = url_for('home')
        return f"""
            <html>
            <head>
                <title>Admin Status</title>
                <style>
                    body {{ display: flex; height: 100vh; flex-direction: column; justify-content: center; align-items: center;}}
                    h1 {{ font-size: 36px; color: red; }}
                    
                </style>
            </head>
            <body>
                <h1>{msg}</h1><br>
                <p>Go to<a href="{home_url}" > HOME</a> .</p>
            </body>
            </html>
        """
    return render_template("superadmin.html", form=form)

@app.route('/profile', methods=["GET", 'POST'])
@login_required
def profile():
    form = ChangePasswordForm()
    if form.validate_on_submit() and request.method == "POST":
        if check_password_hash(current_user.password, form.old_password.data):
            new_hashed_and_salted_pass = hash_password(form.new_password.data)
            user = User.query.filter_by(email=current_user.email).first()
            user.password = new_hashed_and_salted_pass
            db.session.commit()
        return redirect(url_for('home'))
    return render_template('profile.html', form=form)

if __name__ == "__main__":
    app.run()