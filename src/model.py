'''
    Our Model class
    This should control the actual "logic" of your website
    And nicely abstracts away the program logic from your page loading
    It should exist as a separate layer to any database or data structure that you might be using
    Nothing here should be stateful, if it's stateful let the database handle it
'''
import os
import hashlib
import view
import string
import random

MIN_PASSWORD_LENGTH = 8

# Initialise our views, all arguments are defaults for the template
import no_sql_db

db_path = 'db/user_database.txt'
cur_path = os.path.dirname(__file__)
user_db_path = os.path.join(cur_path, db_path)

page_view = view.View()

#-----------------------------------------------------------------------------
# Index
#-----------------------------------------------------------------------------

def index():
    '''
        index
        Returns the view for the index
    '''
    return page_view("index")

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

    # By default assume good creds
    login = False
    err_str = "Incorrect Username or Password"

    database = no_sql_db.database
    entry = database.search_table("users", "username", username)

    if entry:
        stored_hash = entry[1]
        salt = entry[2]
        computed_hash = hashlib.sha256((password + salt).encode()).hexdigest()
        if computed_hash == stored_hash:
            print("Password matches")
            login = True


    if login:
        return (True, page_view("msg_window"))
    else:
        return (False, page_view("login", reason=err_str))

#-----------------------------------------------------------------------------
# Register
#-----------------------------------------------------------------------------

def register_form():
    '''
        login_form
        Returns the view for the login_form
    '''
    return page_view("register")

#-----------------------------------------------------------------------------

def generate_salt64():
    '''
        returns a random 64 byte string
    '''
    return ''.join(random.choice(string.ascii_letters) for char in range(64))

# Create new account
def register_new(username, password, reentered):
    '''
        register_new
        Checks usernames and passwords

        :: username :: The username
        :: password :: The password

        Returns either a view for valid credentials, or a view for invalid credentials
    '''

    if not password == reentered:
        print("password not matching")
        return page_view("password_not_matching")

    if not len(password) >= MIN_PASSWORD_LENGTH:
        print(f"password must be longer than {MIN_PASSWORD_LENGTH} characters")
        return page_view("password_too_short")
    salt = generate_salt64()
    hash_string = hashlib.sha256((password + salt).encode()).hexdigest()

    database = no_sql_db.database

    entry = database.search_table("users", "username", username)

    # User exists
    if entry:
        print("user already exists")
        return page_view("user_taken")
    else:
        database.create_table_entry("users", [username, hash_string, salt])

    print("successfully created user: " + username)
    return page_view("register_success")

#-----------------------------------------------------------------------------
# About
#-----------------------------------------------------------------------------

def about():
    '''
        about
        Returns the view for the about page
    '''
    return page_view("about", garble=about_garble())



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
