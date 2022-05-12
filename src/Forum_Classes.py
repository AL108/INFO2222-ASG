class Forum:
    def __init__(self, name, creator):
        self.name = name
        self.creator = creator
        self.admins = [creator]
        self.posts = []
        self.banned = []
    
    # creator functions
    def get_creator(self):
        return self.creator

    # admin functions
    def get_admins(self):
        return self.admins

    def add_admin(self, username):
        self.admins.append(username)
    
    def remove_admin(self, username):
        self.admins.remove(username)
    
    # post functions
    def get_posts(self):
        return self.posts

    def add_post(self, post):
        self.posts.append(post)
    
    def remove_post(self, postname):
        for i in self.posts:
            if i.get_name() == postname:
                self.posts.remove(i)
    
    # ban funtions
    def get_banned(self):
        return self.banned

    def ban(self, username):
        self.banned.append(username)
    
    def unban(self, username):
        self.banned.remove(username)
    
    # name functions
    
    def set_name(self, name):
        self.name = name
    
    def get_name(self):
        return self.name
    
class Post:
    def __init__(self, username , title, body, timestamp):
        self.username = username
        self.title = title
        self.body = body
        self.timestamp = timestamp
    
    # username functions
    def set_username(self, username):
        self.username = username
    
    def get_username(self):
        return self.username
    
    #title functions
    def set_title(self, title):
        self.title = title
    
    def get_title(self):
        return self.title
    
    # body functions
    def set_body(self, body):
        self.body = body
    
    def get_body(self):
        return self.body
    
    # timestamp functions
    def set_timestamp(self, timestamp):
        self.timestamp = timestamp
    
    def get_timestamp(self):
        return self.timestamp

class Comment:
    def __init__(self, username, body):
        self.username = username
        self.body = body
    
    # username functions
    def set_username(self, username):
        self.username = username
    
    def get_username(self):
        return self.username

    # body functions
    def set_body(self, body):
        self.body = body
    
    def get_body(self):
        return self.body

