from calendar import month

from flask import Flask, jsonify, render_template, request, flash, redirect, url_for
import smtplib
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String,Text
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SubmitField
from wtforms.validators import DataRequired, Email
from flask_ckeditor import CKEditorField,CKEditor
from flask_bootstrap import Bootstrap5
import bleach
from datetime import datetime


class ContactForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired(message="Please enter your name.")])
    email = StringField("Email", validators=[DataRequired(message="Please enter your email."), Email()])
    phone = StringField("Phone Number")  # Optional field
    message = TextAreaField("Message", validators=[DataRequired(message="Please enter your message.")])
    submit = SubmitField("Submit")

# CREATE DB
class Base(DeclarativeBase):
    pass

app = Flask(__name__)
app.config["SECRET_KEY"] = "ehbfiubewkb fiubfuwehfu oehu"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///posts.db'
app.config['CKEDITOR_PKG_TYPE'] = 'full'  # Load the full CKEditor package
ckeditor = CKEditor(app)
bootstrap = Bootstrap5(app)
db = SQLAlchemy(model_class=Base)
db.init_app(app)


class NewPostForm(FlaskForm):
    title = StringField("Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    author = StringField("Author", validators=[DataRequired()])
    img_url = StringField("Background Image URL", validators=[DataRequired(message="Choose a dark one!!!!")])
    body = CKEditorField('Body')
    submit = SubmitField("Submit Post")

class BlogPost(db.Model):
    __tablename__ = "blog_post"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    subtitle: Mapped[str] = mapped_column(String(250), nullable=False)
    date: Mapped[str] = mapped_column(String(250), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    author: Mapped[str] = mapped_column(String(250), nullable=False)
    img_url: Mapped[str] = mapped_column(String(250), nullable=False)


with app.app_context():
    db.create_all()

my_email = "rajrishi0109@gmail.com"  # your email
password = "_____________________"  # your password


def get_blog_posts():
    # response = requests.get(url="https://api.npoint.io/b6f4bf5ce0ce3ba99575")
    # response.raise_for_status()
    # return response.json()
    with app.app_context():
        posts = db.session.execute(db.select(BlogPost)).scalars().all()
        return posts

def send_email(message):
    with smtplib.SMTP("smtp.gmail.com") as connection:
        connection.starttls()
        connection.login(user=my_email, password=password)
        connection.sendmail(from_addr=my_email, to_addrs=my_email, msg=message)

def get_date():
    monthsList = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November",
                  "December"]
    today = datetime.today().date()
    return f"{monthsList[today.month - 1]} {today.day},{today.year}"

@app.route('/')
def home():
    posts = get_blog_posts()
    return render_template("home.html", posts=posts)


@app.route('/post/<int:post_id>')
def blog(post_id):
    post = db.session.execute(db.select(BlogPost).where(BlogPost.id == post_id)).scalar()
    return render_template('post.html', blog_post=post )


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
    posts = get_blog_posts()
    return render_template('about.html')


@app.route('/new-post', methods=["POST", "GET"])
def make_post():
    form = NewPostForm()
    if request.method == "POST" and form.validate_on_submit():
        # Clean the body content before saving it to the database
        clean_body = bleach.clean(form.body.data,
                                  tags=['p', 'b', 'i', 'em', 'strong', 'u', 'a', 'ul', 'ol', 'li', 'br'],
                                  attributes={'a': ['href', 'title']}, strip=True)

        # Create new blog post and save to the database
        new_post = BlogPost(
            title=form.title.data,
            body=clean_body,
            subtitle=form.subtitle.data,
            img_url=form.img_url.data,
            author=form.author.data,
            date=get_date()
        )
        db.session.add(new_post)
        db.session.commit()
        flash('Post created successfully!', 'success')
        return redirect(url_for('home'))
    return render_template("make-post.html", form=form)

@app.route("/delete-post", methods=["GET"])
def delete():
    post_id = request.args.get("post_id")
    post = db.session.execute(db.select(BlogPost).where(BlogPost.id == post_id)).scalar()
    db.session.delete(post)
    db.session.commit()
    return redirect(url_for('home'))

@app.route('/edit-post/<int:post_id>', methods=["GET", "POST"])
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

if __name__ == "__main__":
    app.run(debug=True)