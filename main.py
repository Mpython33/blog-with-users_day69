from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
from functools import wraps
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Table, Column, Integer, ForeignKey
from flask_gravatar import Gravatar
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")      # moved to heroku
# app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)
gravatar = Gravatar(app, size=100, rating='g', default='retro', force_default=False, force_lower=False, use_ssl=False, base_url=None)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')    #postgres on heroku
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# user login manager
login_manager = LoginManager()
login_manager.init_app(app)
# secret key already setup above


@login_manager.user_loader
def load_user(author_id):
    return User.query.get(author_id)


#Create admin-only decorator
def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        #If id is not 1 then return abort with 403 error
        if current_user.id != 1:           # not current_user.is_anonymous or # not needed
            print(f"Current user!= 1 {current_user.id}  {current_user.is_anonymous}")
            return abort(403)
        #Otherwise continue with the route function
        return f(*args, **kwargs)
    return decorated_function

##CONFIGURE TABLES


##CREATE TABLE IN DB
class User(UserMixin, db.Model):
    __tablename__ ="user"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(100))
    # This will act like a List of BlogPost objects attached to each User.
    # The "author" refers to the author property in the BlogPost class.
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="comment_author")
# #Line below only required once, when creating DB.
# db.create_all()



class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    #Create Foreign Key, "users.id" the users refers to the tablename of User.
    author_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    #Create reference to the User object, the "posts" refers to the posts protperty in the User class.
    author = relationship("User", back_populates="posts")
    # author = db.Column(db.String(250), nullable=False)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    # user_id = Column(Integer, ForeignKey('user.id'))
    # ***************Parent Relationship*************#
    comments = relationship("Comment", back_populates="parent_post")

class Comment(db.Model):
    __tablename__ = "comment"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    comment_author = relationship("User", back_populates="comments")
    #***************Child Relationship*************#
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    parent_post = relationship("BlogPost", back_populates="comments")
    text = db.Column(db.Text, nullable=False)


# #Line below only required once, when creating DB.
db.create_all()
db.session.commit()



@app.route('/', methods=['GET', 'POST'])
def get_all_posts():
    posts = BlogPost.query.all()
    # Every render_template has a logged_in variable set.
    # print(current_user.is_authenticated)
    # print(current_user)
    return render_template("index.html", all_posts=posts,  current_user=current_user)




@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if request.method == "POST":

        if User.query.filter_by(email=request.form.get('email')).first():
            # user already exists
            flash("You've already signed up with that email, log in instead!")
            return redirect(url_for('login'))

        hash_and_salted_password = generate_password_hash(
            request.form.get('password'),
            method='pbkdf2:sha256',
            salt_length=8
        )
        print(hash_and_salted_password)

        new_user = User(
            name=request.form['name'],
            email=form.email.data,     # works only in WTF forms while request.form works in html and wtf
            password=hash_and_salted_password
        )
        # print(name, email, password)
        db.session.add(new_user)
        db.session.commit()

        # Log in and authenticate user after adding details to database.
        login_user(new_user)
        return redirect(url_for('get_all_posts'))

    return render_template("register.html", form=form, current_user=current_user)


@app.route('/login', methods=['POST', 'GET'])
def login():
    loginform = LoginForm()
    if request.method == 'POST':
        email = loginform.email.data
        password = loginform.password.data
        # find user in DB
        user = User.query.filter_by(email=email).first()
        print(user)
        print(email)
        print(password)
        if not user:
            print(email)
            flash("that email doesnt exist please try again")
            print("email doestn exist")
            return redirect(url_for('login'))
        # email exists check password is incorrect
        elif not check_password_hash(user.password, password):
            flash("incorrect password")
            print("incorrect password")
            return redirect(url_for('login'))
        else:
            if check_password_hash(user.password, password):
                print(f"{user} logged in")
                login_user(user)
                return redirect(url_for('get_all_posts'))
    print("outside if")
    return render_template("login.html", form=loginform, current_user=current_user)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=['GET', "POST"])
def show_post(post_id):
    comment_form = CommentForm()
    requested_post = BlogPost.query.get(post_id)
    if comment_form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You need to login")
            return redirect(url_for('login'))

        new_comment = Comment(
            text=comment_form.comment.data,
            comment_author=current_user,
            parent_post=requested_post
        )
        db.session.add(new_comment)
        db.session.commit()

    print("in post ")
    return render_template("post.html", post=requested_post, current_user=current_user, form=comment_form)


@app.route("/about")
def about():
    return render_template("about.html", current_user=current_user)


@app.route("/contact")
def contact():
    return render_template("contact.html", current_user=current_user)


@app.route("/new-post", methods=["GET", "POST"])
# Mark with decorator
@admin_only
def add_new_post():
    # print("in add_new_post")
    form = CreatePostForm()
    if form.validate_on_submit():
        # current_user_id = int(current_user.id)
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            # author=current_user.name,
            date=date.today().strftime("%B %d, %Y"),
            author_id=current_user.id
        )
        # print("adding newpost to DB")
        # print(current_user)
        # print(type(current_user.id))
        # print(type(current_user_id))
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, current_user=current_user)


@app.route("/edit-post/<int:post_id>", methods=['GET', "POST"])
#Mark with decorator
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )

    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author_id = current_user.id
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form, current_user=current_user)


@app.route("/delete/<int:post_id>")
#Mark with decorator
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    # app.run(host='0.0.0.0', port=5000)
    app.run(debug=True)