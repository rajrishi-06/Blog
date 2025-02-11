import smtplib
from typing import cast
from sqlalchemy import Integer, String, Text, Boolean, or_
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SubmitField, PasswordField, EmailField
from wtforms.validators import DataRequired, Email, Length, Regexp
from flask_ckeditor import CKEditorField,CKEditor
from flask_bootstrap import Bootstrap5
import bleach
from datetime import datetime
from flask import Flask, render_template, request, url_for, redirect, flash,  jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, joinedload, QueryableAttribute
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user
import os
from dotenv import load_dotenv
load_dotenv()
admins = os.getenv("ADMINS")

class ContactForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired(message="Please enter your name.")])
    email = StringField("Email", validators=[DataRequired(message="Please enter your email."), Email()])
    phone = StringField("Phone Number")  # Optional field
    message = TextAreaField("Message", validators=[DataRequired(message="Please enter your message.")])
    submit = SubmitField("Submit")

class Base(DeclarativeBase):
    pass

app = Flask(__name__)
app.config["SECRET_KEY"] = "ehbfiubewkb fiubfuwehfu oehu"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///posts.db'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///comments.db'
app.config['CKEDITOR_PKG_TYPE'] = 'full'
app.config['CKEDITOR_SERVE_LOCAL'] = True
app.config['CKEDITOR_HEIGHT'] = 200
ckeditor = CKEditor(app)
bootstrap = Bootstrap5(app)
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
    submit = SubmitField("Submit Post")


class RegisterForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    email = EmailField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[
        DataRequired(),
        Length(min=8, message="Password must be at least 8 characters long."),
        Regexp(r'^(?=.*[A-Z]).+$', message="Password must contain at least one uppercase letter.")
    ])
    submit = SubmitField("Sign Me Up")

class LoginForm(FlaskForm):
    email = EmailField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[
        DataRequired(),
        Length(min=8, message="Password must be at least 8 characters long."),
        Regexp(r'^(?=.*[A-Z]).+$', message="Password must contain at least one uppercase letter.")
    ])
    submit = SubmitField("Let Me In")

class CommentForm(FlaskForm):
    comment = CKEditorField('Comment')
    submit = SubmitField('Post Comment')


class BlogPost(db.Model):
    __tablename__ = "blog_post"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    subtitle: Mapped[str] = mapped_column(String(250), nullable=False)
    date: Mapped[str] = mapped_column(String(250), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    author: Mapped[str] = mapped_column(String(250), nullable=False)
    img_url: Mapped[str] = mapped_column(String(250), nullable=False)
    user_id: Mapped[int] = mapped_column(Integer, db.ForeignKey("user.id"), nullable=False)

    user = db.relationship("User", back_populates="posts")
    comments = db.relationship("Comment", back_populates="post", cascade="all, delete-orphan")


class User(db.Model, UserMixin):
    __tablename__ = "user"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(100), unique=True)
    password: Mapped[str] = mapped_column(String(100))
    name: Mapped[str] = mapped_column(String(1000))
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



with app.app_context():
    db.create_all()

my_email = os.getenv("EMAIL")  # your email
my_email_password = os.getenv("EMAIL_PASSWORD")


def get_blog_posts():
    with app.app_context():
        posts = BlogPost.query.options(joinedload(cast(QueryableAttribute, BlogPost.user))).all()
        return posts

from flask_login import current_user

def get_users_blog_posts():
    with app.app_context():
        if current_user.is_authenticated and current_user.is_admin:
            return get_blog_posts()  # Admin sees all posts
        elif current_user.is_authenticated:
            return BlogPost.query.options(joinedload(cast(QueryableAttribute, BlogPost.user))).where(BlogPost.user_id == current_user.id).all()
            # return db.session.execute(
            #     db.select(BlogPost).where()
            # ).scalars().all()  # Regular user sees only their own posts

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

# Flask-Login user loader
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
            user_id= current_user.id
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

    if form.validate_on_submit():
        post.title = form.title.data
        post.subtitle = form.subtitle.data
        post.author = form.author.data
        post.img_url = form.img_url.data
        post.body = form.body.data
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
        user = db.session.execute(db.select(User).where(User.email == form.email.data.lower())).scalar_one_or_none()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user, remember=True)
            return redirect(url_for('home'))
        else:
            flash('Invalid email or password. Please try again.', 'danger')
    return render_template('login.html', form=form)

@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if request.method == "POST" and form.validate_on_submit():
        user_email = form.email.data.lower()
        if db.session.execute(db.select(User).where(User.email == user_email)).scalar_one_or_none():
            flash('Email already exists. Please log in.', 'warning')
            return redirect(url_for('login'))
        hashed_and_salted_password = generate_password_hash(
            password=form.password.data,
            method="pbkdf2:sha256:600000",
            salt_length=8
        )
        new_user = User(
            name=form.name.data,
            email=user_email.lower(),
            password=hashed_and_salted_password,
            is_admin=True if user_email in admins else False
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


@app.route('/search')
def search():
    query = request.args.get('q', '')
    app.logger.info("Search query received: %s", query)

    if query:
        results = BlogPost.query.outerjoin(BlogPost.user).filter(
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
        # Determine which author name to display.
        # Use the stored author field if present, otherwise use the user's name.
        author_display = post.author if post.author else (post.user.name if post.user else 'Unknown')
        results_list.append({
            'id': post.id,
            'title': post.title,
            'author': author_display,
            'url': url_for('blog', post_id=post.id)  # Ensure this endpoint exists.
        })
    return jsonify(results_list)

if __name__ == "__main__":
    app.run(debug=True)