import os
from dotenv import load_dotenv

from flask import Flask, render_template, request, flash, redirect, session, g
from flask_debugtoolbar import DebugToolbarExtension
from sqlalchemy.exc import IntegrityError

from forms import UserAddForm, LoginForm, MessageForm, CSRFForm
from models import db, connect_db, User, Message

load_dotenv()

CURR_USER_KEY = "curr_user"

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = os.environ['DATABASE_URL']
app.config['SQLALCHEMY_ECHO'] = False
app.config['DEBUG_TB_INTERCEPT_REDIRECTS'] = True
app.config['SECRET_KEY'] = os.environ['SECRET_KEY']
toolbar = DebugToolbarExtension(app)

connect_db(app)



##############################################################################
# User signup/login/logout


@app.before_request
def add_user_to_g():
    """If we're logged in, add curr user to Flask global."""

    if CURR_USER_KEY in session:
        g.user = User.query.get(session[CURR_USER_KEY])

    else:
        g.user = None

@app.before_request
def create_CSRF_Protection():
    """ Establish the global variable in flask object "g" to make logout a valid
    form on on every page"""

    g.csrf_form = CSRFForm()


def do_login(user):
    """Log in user."""

    session[CURR_USER_KEY] = user.id


def do_logout():
    """Log out user."""

    if CURR_USER_KEY in session:
        del session[CURR_USER_KEY]



@app.route('/signup', methods=["GET", "POST"])
def signup():
    """Handle user signup.

    Create new user and add to DB. Redirect to home page.

    If form not valid, present form.

    If the there already is a user with that username: flash message
    and re-present form.
    """
#TODO: userimage still showing up despite being logged out in route.

    do_logout()

    form = UserAddForm()

    if form.validate_on_submit():
        try:
            user = User.signup(
                username=form.username.data,
                password=form.password.data,
                email=form.email.data,
                image_url=form.image_url.data or User.image_url.default.arg,
            )
            db.session.commit()

        except IntegrityError:
            flash("Username already taken", 'danger')
            return render_template('users/signup.html', form=form)

        do_login(user)

        return redirect("/")

    else:
        return render_template('users/signup.html', form=form)


@app.route('/login', methods=["GET", "POST"])
def login():
    """Handle user login and redirect to homepage on success.
    If user is logged in, will redirect to user's homepage.
    """

    if g.user:
        return redirect('/')

    form = LoginForm()

    if form.validate_on_submit():
        user = User.authenticate(
            form.username.data,
            form.password.data,
        )

        if user:
            do_login(user)
            flash(f"Hello, {user.username}!", "success")
            return redirect("/")

        flash("Invalid credentials.", 'danger')

    return render_template('users/login.html', form=form)


@app.post('/logout')
def logout():
    """Handle logout of user and redirect to homepage."""

    # form = g.csrf_form

    # IMPLEMENT THIS AND FIX BUG
    # DO NOT CHANGE METHOD ON ROUTE

    if g.csrf_form.validate_on_submit:
        do_logout()
        flash('You have succesfully logged out!','success')

    return redirect('/login')


##############################################################################
# General user routes:

@app.get('/users')
def list_users():
    """Page with listing of users.

    Can take a 'q' param in querystring to search by that username.
    """

    if not g.user:
        flash("Access unauthorized.", "danger")
        return redirect("/")

    search = request.args.get('q')

    if not search:
        users = User.query.all()
    else:
        users = User.query.filter(User.username.like(f"%{search}%")).all()

    return render_template('users/index.html', users=users)


@app.get('/users/<int:user_id>')
def show_user(user_id):
    """Show user profile."""
    # TODO: Should showing a user profile be allowed for ALL logged in users?
    if not g.user:
        flash("Access unauthorized.", "danger")
        return redirect("/")

    user = User.query.get_or_404(user_id)

    return render_template('users/show.html', user=user)


@app.get('/users/<int:user_id>/following')
def show_following(user_id):
    """Show list of people this user is following."""
    # TODO: Should showing a user's folowers be allowed for ALL users?
    if not g.user:
        flash("Access unauthorized.", "danger")
        return redirect("/")

    user = User.query.get_or_404(user_id)
    return render_template('users/following.html', user=user)


@app.get('/users/<int:user_id>/followers')
def show_followers(user_id):
    """Show list of followers of this user."""
    # TODO: Should showing a user's folowees be allowed for ALL users
    if not g.user:
        flash("Access unauthorized.", "danger")
        return redirect("/")

    user = User.query.get_or_404(user_id)
    return render_template('users/followers.html', user=user)


@app.post('/users/follow/<int:follow_id>')
def start_following(follow_id):
    """Add a follow for the currently-logged-in user.

    Redirect to following page for the current for the current user.
    """
    # TODO: Should adding a follower to the current user be allowed for ALL users
    if not g.user:
        flash("Access unauthorized.", "danger")
        return redirect("/")

    followed_user = User.query.get_or_404(follow_id)
    g.user.following.append(followed_user)
    db.session.commit()

    return redirect(f"/users/{g.user.id}/following")


@app.post('/users/stop-following/<int:follow_id>')
def stop_following(follow_id):
    """Have currently-logged-in-user stop following this user.

    Redirect to following page for the current for the current user.
    """
    # TODO: Should the current user be allowed to unfollow any user?
    if not g.user:
        flash("Access unauthorized.", "danger")
        return redirect("/")

    followed_user = User.query.get_or_404(follow_id)
    g.user.following.remove(followed_user)
    db.session.commit()

    return redirect(f"/users/{g.user.id}/following")


@app.route('/users/profile', methods=["GET", "POST"])
def profile():
    """Update profile for current user."""

    # IMPLEMENT THIS
    # Check that user is logged in
    # TODO: Check user matches profile? Make or condition
    if not g.user:
        flash("Access unauthorized.", "danger")
        return redirect("/")

@app.post('/users/delete')
def delete_user():
    """Delete user.

    Redirect to signup page.
    """

    if not g.user:
        flash("Access unauthorized.", "danger")
        return redirect("/")

    do_logout()
    # TODO: Why do messages need to be deleted prior to user deletion but not
    # the following/followed records in the follows table?
    user_messages = g.user.messages
    for message in user_messages:
        db.session.delete(message)
        db.session.commit()

    db.session.delete(g.user)
    db.session.commit()

    return redirect("/signup")

# Below route required user to log back in when deleting, kept code for future
# use but will no use for now as it changes too much of base code.
# @app.route('/users/delete', methods = ["GET", "POST"])
# def delete_user():
#     """Delete user.

#     Redirect to signup page.
#     """

#     #FIXME: change into a post route revert changes

#     if not g.user:
#         flash("Access unauthorized.", "danger")
#         return redirect("/")

#     form = LoginForm()

#     #FIXME: why is our flash showing up on homepage after deleting an account

#     # flash(
#     #     "This action cannot be undone. Are you sure you would like to" +
#     #     "delete your account and messages?",
#     #     'danger'
#     # )
#     if form.validate_on_submit():

#         user = User.authenticate(
#             form.username.data,
#             form.password.data,
#         )

#         if user:
#             user_messages = g.user.messages
#             for message in user_messages:
#                 db.session.delete(message)
#                 db.session.commit()
#             do_logout()
#             db.session.delete(g.user)
#             db.session.commit()
#             return redirect('/')

#         else:
#             flash("Invalid credentials.", 'danger')




#     return render_template("users/login-to-delete.html", form=form)


##############################################################################
# Messages routes:

@app.route('/messages/new', methods=["GET", "POST"])
def add_message():
    """Add a message:

    Show form if GET. If valid, update message and redirect to user page.
    """
    # TODO: Should all users be able to add their own messages?
    if not g.user:
        flash("Access unauthorized.", "danger")
        return redirect("/")

    form = MessageForm()

    if form.validate_on_submit():
        msg = Message(text=form.text.data)
        g.user.messages.append(msg)
        db.session.commit()

        return redirect(f"/users/{g.user.id}")

    return render_template('messages/create.html', form=form)


@app.get('/messages/<int:message_id>')
def show_message(message_id):
    """Show a message."""
    # TODO: Should all users be able to view any message?
    if not g.user:
        flash("Access unauthorized.", "danger")
        return redirect("/")

    msg = Message.query.get_or_404(message_id)
    return render_template('messages/show.html', message=msg)


@app.post('/messages/<int:message_id>/delete')
def delete_message(message_id):
    """Delete a message.

    Check that this message was written by the current user.
    Redirect to user page on success.
    """
    # TODO: Should all users be able to delete their own message?
    if not g.user:
        flash("Access unauthorized.", "danger")
        return redirect("/")

    msg = Message.query.get_or_404(message_id)

    try:
        g.user.messages.remove(msg)
        db.session.delete(msg)
        db.session.commit()
        return redirect(f"/users/{g.user.id}")

    except ValueError:
        flash('Message deletion unsuccesful','warning')
        return redirect(f"/users/{g.user.id}")



##############################################################################
# Homepage and error pages


@app.get('/')
def homepage():
    """Show homepage:

    - anon users: no messages
    - logged in: 100 most recent messages of self & followed_users
    """
    # TODO: How to limit messages only to own and followers? Don't want
    # unfollowed messages...
    if g.user:
        messages = (Message
                    .query
                    .order_by(Message.timestamp.desc())
                    .limit(100)
                    .all())

        return render_template('home.html', messages=messages)

    else:
        return render_template('home-anon.html')


@app.after_request
def add_header(response):
    """Add non-caching headers on every request."""

    # https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control
    response.cache_control.no_store = True
    return response
