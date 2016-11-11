import webapp2
import re
import hmac
from google.appengine.ext import db
from user import User
from post import Post
from comment import Comment
from userlikes import Like
import jinja2env

secret = 'super secret secret'

# Helper functions


def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())


def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

# Main Handler


class Handler(webapp2.RequestHandler):

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return jinja2env.jinja_render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


def blog_key(name='default'):
    return db.Key.from_path('blogs', name)


# Default Page
class Main(Handler):

    def get(self):
        deleted_post_id = self.request.get('deleted_post_id')
        posts = Post.all().order('-created')
        self.render('main.html', posts=posts, deleted_post_id=deleted_post_id)

# More Helper functions

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")


def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")


def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')


def valid_email(email):
    return not email or EMAIL_RE.match(email)


# Sign up page which validates and register the user
class Signup(Handler):

    def get(self):
        self.render("signup.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        # storing parameters

        params = dict(username=self.username,
                      email=self.email)

        # validation checks

        if not valid_username(self.username):
            params['error_username'] = "Not a valid username"
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "Not a valid password"
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Passwords doesnt match"
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "Not a valid email"
            have_error = True

        if have_error:
            self.render('signup.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError


class Register(Signup):

    def done(self):

        # Makes sure the user doesn't already exist

        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup.html', error_username=msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/')


# User login details validation
class Login(Handler):

    def get(self):
        self.render('login.html', error=self.request.get('error'))

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/')
        else:
            msg = 'Invalid login'
            self.render('login.html', error=msg)


# Clears the cookies and safely get backs to default Main page
class Logout(Handler):

    def get(self):
        self.logout()
        self.redirect('/')


# Routes back to post page
class PostPage(Handler):

    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        comments = db.GqlQuery("select * from Comment where post_id = " +
                               post_id +
                               " order by created desc")

        likes = db.GqlQuery("select * from Like where post_id=" + post_id)

        if not post:
            self.error(404)
            return

        error = self.request.get('error')

        self.render("postpage.html", post=post, NumLikes=likes.count(),
                    comments=comments, error=error)

    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        c = ""
        if(self.user):

            # On clicking like, post-like value increases.

            if(self.request.get('like') and
               self.request.get('like') == "update"):
                likes = db.GqlQuery("select * from Like where post_id = " +
                                    post_id + " and user_id = " +
                                    str(self.user.key().id()))

                if self.user.key().id() == post.user_id:
                    self.redirect("/blog/" + post_id +
                                  "?error=You cannot like your " +
                                  "post.!!")
                    return
                elif likes.count() == 0:
                    l = Like(parent=blog_key(), user_id=self.user.key().id(),
                             post_id=int(post_id))
                    l.put()

            # On commenting, it creates new comment tuple

            if(self.request.get('comment')):
                c = Comment(parent=blog_key(), user_id=self.user.key().id(),
                            post_id=int(post_id),
                            comment=self.request.get('comment'))
                c.put()
        else:
            self.redirect("/login?error=Please login")
            return

        comments = db.GqlQuery("select * from Comment where post_id = " +
                               post_id + "order by created desc")

        likes = db.GqlQuery("select * from Like where post_id=" + post_id)

        self.render("postpage.html", post=post, NumLikes=likes.count(),
                    comments=comments)


# New Post Page is rendered
class NewPost(Handler):

    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            self.redirect('/blog')

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p = Post(parent=blog_key(), user_id=self.user.key().id(),
                     subject=subject, content=content)
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject,
                        content=content, error=error)


# Deletes the current post
class DeletePost(Handler):

    def get(self, post_id):
        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            if post.user_id == self.user.key().id():
                post.delete()
                self.redirect("/?deleted_post_id=" + post_id)
            else:
                self.redirect("/blog/" + post_id +
                              "?error=No access to delete the record")
        else:
            self.redirect("/login?error=You need to be logged, in order" +
                          " to delete your post!!")


# Edits the current post
class EditPost(Handler):

    def get(self, post_id):
        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            if post.user_id == self.user.key().id():
                self.render("editpost.html", subject=post.subject,
                            content=post.content)
            else:
                self.redirect("/blog/" + post_id + "?error=No proper access" +
                              " to edit this post")
        else:
            self.redirect("/login?error=Please login in to edit the post")

    def post(self, post_id):
        if not self.user:
            self.redirect('/blog')

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            post.subject = subject
            post.content = content
            post.put()
            self.redirect('/blog/%s' % post_id)
        else:
            error = "subject and content, please!"
            self.render("editpost.html", subject=subject,
                        content=content, error=error)


# Deletes the comment of the current user
class DeleteComment(Handler):

    def get(self, post_id, comment_id):
        if self.user:
            key = db.Key.from_path('Comment', int(comment_id),
                                   parent=blog_key())
            c = db.get(key)
            if c.user_id == self.user.key().id():
                c.delete()
                self.redirect("/blog/" + post_id + "?deleted_comment_id=" +
                              comment_id)
            else:
                self.redirect("/blog/" + post_id +
                              "?error=No proper access " +
                              "to delete this comment")
        else:
            self.redirect("/login?error=Please login in to delete the comment")


# Edits the comment of current user
class EditComment(Handler):

    def get(self, post_id, comment_id):
        if self.user:
            key = db.Key.from_path('Comment', int(comment_id),
                                   parent=blog_key())
            c = db.get(key)
            if c.user_id == self.user.key().id():
                self.render("editcomment.html", comment=c.comment)
            else:
                self.redirect("/blog/" + post_id +
                              "?error=No proper access to edit this comment")

        else:
            self.redirect("/login?error=Please login in to edit the comment")

    def post(self, post_id, comment_id):
        """
            Updates post.
        """
        if not self.user:
            self.redirect('/blog')

        comment = self.request.get('comment')

        if comment:
            key = db.Key.from_path('Comment',
                                   int(comment_id), parent=blog_key())
            c = db.get(key)
            c.comment = comment
            c.put()
            self.redirect('/blog/%s' % post_id)
        else:
            error = "subject and content, please!"
            self.render("editpost.html", subject=subject,
                        content=content, error=error)

app = webapp2.WSGIApplication([
    ('/?', Main),
    ('/blog/([0-9]+)', PostPage),
    ('/blog/newpost', NewPost),
    ('/blog/deletepost/([0-9]+)', DeletePost),
    ('/blog/editpost/([0-9]+)', EditPost),
    ('/blog/deletecomment/([0-9]+)/([0-9]+)',
     DeleteComment),
    ('/blog/editcomment/([0-9]+)/([0-9]+)',
     EditComment),
    ('/signup', Register),
    ('/login', Login),
    ('/logout', Logout),
],
    debug=True)
