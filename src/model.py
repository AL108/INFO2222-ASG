'''
    Our Model class
    This should control the actual "logic" of your website
    And nicely abstracts away the program logic from your page loading
    It should exist as a separate layer to any database or data structure that you might be using
    Nothing here should be stateful, if it's stateful let the database handle it
'''
import os
import hashlib
import time
import view
import string
import random
from ID_generator import ID_generator

MIN_PASSWORD_LENGTH = 8
id_generator = ID_generator()

# Initialise our views, all arguments are defaults for the template
import no_sql_db

cur_path = os.path.dirname(__file__)
user_db_path = os.path.join(cur_path, 'db/user_database.txt')
pubkey_db_path = os.path.join(cur_path, 'db/public_key_database.txt')

page_view = view.View()

#-----------------------------------------------------------------------------
# Homepage
#-----------------------------------------------------------------------------

def home():
    '''
        home
        Returns the view for the home
    '''
    return page_view("home")

#-----------------------------------------------------------------------------
# Login
#-----------------------------------------------------------------------------

def login_form():
    '''
        login_form
        Returns the view for the login_form
    '''
    return page_view("login")

#-----------------------------------------------------------------------------

# Check the login credentials
def login_check(username, password):
    '''
        login_check
        Checks usernames and passwords
        :: username :: The username
        :: password :: The password
        Returns either a view for valid credentials, or a view for invalid credentials
    '''

    login = False
    err_str = "Incorrect Username or Password"

    database = no_sql_db.database
    entry = database.search_table("users", "username", username)

    if entry:
        stored_hash = entry[1]
        salt = entry[2]
        computed_hash = hashlib.sha256((password + salt).encode()).hexdigest()
        if computed_hash == stored_hash:
            # print("Password matches")
            login = True


    if login:
        return (True, page_view("msg_window"))
    else:
        return (False, page_view("invalid", reason=err_str))

#-----------------------------------------------------------------------------
# Register
#-----------------------------------------------------------------------------

def register_form():
    '''
        login_form
        Returns the view for the login_form
    '''
    return page_view("register")

def generate_salt64():
    '''
        returns a random 64 byte string
    '''
    return ''.join(random.choice(string.ascii_letters) for char in range(64))

# Create new account
def register_new(username, hashed, salt):
    '''
        register_new
        Checks usernames and passwords
        :: username :: The username
        :: password :: The password
        Returns either a view for valid credentials, or a view for invalid credentials
    '''

    # Edge cases
    #if not password == reentered:
        # print("password not matching")
        #return ("not matching", page_view("password_not_matching"))
    #if not len(password) >= MIN_PASSWORD_LENGTH:
        # print(f"password must be longer than {MIN_PASSWORD_LENGTH} characters")
        #return ("too short", page_view("password_too_short"))

    # Salt and hash
    #salt = generate_salt64()
    #hash_string = hashlib.sha256((password + salt).encode()).hexdigest()

    database = no_sql_db.database

    entry = database.search_table("users", "username", username)

    # User exists
    if entry:
        # print("user already exists")
        return ("user taken", page_view("user_taken"))


    print("successfully created user: " + username)
    database.create_table_entry("users", [username, hashed, salt, ""])

    return ("success", page_view("register_success"))

#-----------------------------------------------------------------------------
# Database Helpers
#-----------------------------------------------------------------------------
# Friends list
def add_friend(username, friend):
    database = no_sql_db.database

    curEntryList = database.get_entries('users', 'username', username)[0]
    curEntryList[3] = curEntryList[3] + ";" + friend

    return database.override_existing_entry('users', 'username', username, curEntryList)

def get_friends_list(username):
    database = no_sql_db.database
    entryList = database.get_entries('users', 'username', username)[0]     #[0] needed because returned value is a list of all found entries
    
    if len(entryList) == 4:
        return entryList[3]

    return None


# Public keys database
def store_public_key(username, public_key):
    database = no_sql_db.database
    database.create_table_entry("public_keys", [username, public_key])

def get_public_key(username):
    '''
    returns entry of public key table
    format username, public key, digital signature
    '''
    database = no_sql_db.database
    entryList = database.search_table('public_keys', 'username', username)
    if entryList:
        return entryList[1]

    return None


# Session keys database
def store_session_key(A_username, enc_Apub_sk, B_username, enc_Bpub_sk, hmac_key, iv):
    database = no_sql_db.database
    # newIV = iv.replace(",","-")
    database.create_table_entry("session_keys", [A_username, enc_Apub_sk, B_username, enc_Bpub_sk, hmac_key, iv])

def get_session_key(sender, recipient):
    '''
    returns entry of public key table
    format username, public key, digital signature
    '''

    database = no_sql_db.database
    entriesList = database.get_entries('session_keys', 'A_username', sender)
    entriesList.extend(database.get_entries('session_keys', 'A_username', recipient))

    for entry in entriesList:
        if entry[0] == sender and entry[2] == recipient:
            # return entry[1]
            # print(entry)
            # entry[5] = entry[5].replace("-",",")
            return entry

        elif entry[2] == sender and entry[0] == recipient:
            # return entry[3]
            # entry[5] = entry[5].replace("-",",")
            return entry

    return None

# Messages database
def store_message(sender, recipient, enc_msg_ts, mac_enc_msg_ts):
    database = no_sql_db.database
    new_encMsg = enc_msg_ts
    database.create_table_entry("messages", [sender, recipient, new_encMsg, mac_enc_msg_ts])

def get_messages(recipient):
    '''
    returns message entries in JSON format
    message entry format is <sender> <recipient> <enc_msg_ts> <mac_enc_ts>
    '''
    database = no_sql_db.database
    entries = database.get_entries("messages", "recipient", recipient)
    return entries
    # to_return = '[\n'
    # for entry in entries:
    #     to_return += '{\n'
    #     to_return += '"sender": "' + entry[0] + '",\n'
    #     to_return += '"recipient": "' + entry[1] + '",\n'
    #     to_return += '"enc_msg_ts": "' + entry[2] + '",\n'
    #     to_return += '"mac_enc_ts": "' + entry[3] + '"\n'
    #     to_return += '}\n'
    # to_return += ']\n'
    # return to_return

#-----------------------------------------------------------------------------
# About
#-----------------------------------------------------------------------------

def about():
    '''
        about
        Returns the view for the about page
    '''
    return page_view("about", garble=about_garble())

#-----------------------------------------------------------------------------
# Forums
#-----------------------------------------------------------------------------
def forums():
    '''
        about
        Returns the view for the about page
    '''
    return page_view("forums")

def get_forums(username):
    '''
        Returns the forum_ids of the forums that the user is subscribed to.
    '''
    database = no_sql_db.database
    res = database.get_entries('forum_subscriptions', 'subscriber', username)
    forum_ids = []
    for i in res:
        forum_ids.append(i[1])
    return forum_ids

def get_forum_name(forum_id):
    '''
        returns the name of the forum with id: 'forum_id'
    '''
    res = no_sql_db.database.search_table('forums', 'forum_id', forum_id)
    if res:
        print(res[1])
        return res[1]
    return res

def get_forum_desc(forum_id):
    '''
        returns the desc of the forum with id: 'forum_id'
    '''
    res = no_sql_db.database.search_table('forums', 'forum_id', forum_id)
    if res:
        print(res[2], "this is a description")
        return res[2]
    return res

def get_forum_admin(forum_id):
    '''
        returns the desc of the forum with id: 'forum_id'
    '''
    res = no_sql_db.database.search_table('forums', 'forum_id', forum_id)
    if res:
        return res[3]
    return res

def get_posts(forum_id):
    '''
        returns the posts for the forum in the following format:
        ['post_id', 'author', 'title', 'body', 'timestamp']
    '''
    database = no_sql_db.database
    return database.get_entries('posts', 'forum_id', forum_id)

def get_comments(post_id):
    '''
        returns the comments for the post in the following format:
        ['post_id', 'author', 'body', 'timestamp']
    '''
    database = no_sql_db.database
    return database.get_entries('comments', 'post_id', post_id)

def get_tags(post_id):
    '''
        returns the tags for the post
    '''
    database = no_sql_db.database
    res = database.get_entries('post_tags', 'post_id', post_id)
    ret = [tag[1] for tag in res]
    return ret

def add_post(forum_id, author, title, body, timestamp, tags=None):
    '''
        adds a post to the forum
    '''
    database = no_sql_db.database
    id = id_generator.generate_id()
    database.create_table_entry('posts', [id, forum_id, author, title, body, timestamp])

def add_comment(post_id, author, body, timestamp):
    '''
        adds a comment to the post    
    '''
    database = no_sql_db.database
    database.create_table_entry('comments', [post_id, author, body, timestamp])

def create_forum(creator, name, description=""):
    '''
        add a forum
    '''
    database = no_sql_db.database
    id = id_generator.generate_id()
    database.create_table_entry('forums', [id, name, description, creator])
    return id

def create_post(creator, title, body, tag, forum_id):
    '''
        note: posts table format:
        ['post_id', 'forum_id', 'author', 'title', 'body', 'timestamp']
    '''
    database = no_sql_db.database
    id = id_generator.generate_id()
    database.create_table_entry('posts', [id, forum_id, creator, title, body, str(int(time.time()*1000.0))])
    if tag:
        database.create_table_entry('post_tags', [id, tag])
    return id

def forum_exists(forum_id):
    database = no_sql_db.database
    return database.search_table('forums', 'forum_id', forum_id)

def subscribe(subscriber, forum_id):
    '''
        subscribe subscriber to forum, returns:
            1, if successful
            -1, if forum does not exist
            0, if already subscribed
    '''
    database = no_sql_db.database
    # check if already subscribed
    r = database.get_entries('forum_subscriptions', 'subscriber', subscriber)
    if r.__contains__([subscriber, forum_id]):
        return 0
    if not forum_exists(forum_id):
        return -1
    database.create_table_entry('forum_subscriptions', [subscriber, forum_id])
    return 1

def get_posts(forum_id):
    '''
        (note) post table format: 
        ['post_id', 'forum_id', 'author', 'title', 'body', 'timestamp']
    '''
    database = no_sql_db.database
    print("forum id:", forum_id)
    ret = database.get_entries('posts', 'forum_id', forum_id)
    print("posts", ret)
    return ret

# Returns a random string each time
def about_garble():
    '''
        about_garble
        Returns one of several strings for the about page
    '''
    garble = ["leverage agile frameworks to provide a robust synopsis for high level overviews.",
    "iterate approaches to corporate strategy and foster collaborative thinking to further the overall value proposition.",
    "organically grow the holistic world view of disruptive innovation via workplace change management and empowerment.",
    "bring to the table win-win survival strategies to ensure proactive and progressive competitive domination.",
    "ensure the end of the day advancement, a new normal that has evolved from epistemic management approaches and is on the runway towards a streamlined cloud solution.",
    "provide user generated content in real-time will have multiple touchpoints for offshoring."]
    return garble[random.randint(0, len(garble) - 1)]

 

#-----------------------------------------------------------------------------
# Friends
#-----------------------------------------------------------------------------

def msg_window():
    '''
        friends
        Returns the view for the friends page
    '''
    return page_view("msg_window")

#-----------------------------------------------------------------------------
# Debug
#-----------------------------------------------------------------------------

def debug(cmd):
    try:
        return str(eval(cmd))
    except:
        pass


#-----------------------------------------------------------------------------
# 404
# Custom 404 error page
#-----------------------------------------------------------------------------

def handle_errors(error):
    error_type = error.status_line
    error_msg = error.body
    return page_view("error", error_type=error_type, error_msg=error_msg)
