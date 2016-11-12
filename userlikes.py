
from google.appengine.ext import db

from user import User


class Like(db.Model):
    user_id = db.IntegerProperty(required=True)
    post_id = db.IntegerProperty(required=True)

    def get_user_name(self):
        user = User.by_id(self.user_id)
        return user.name
