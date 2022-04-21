'''
    This file will handle our typical Bottle requests and responses
    You should not have anything beyond basic page loads, handling forms and
    maybe some simple program logic
'''

from bottle import route, get, post, error, request, static_file, response, redirect

import model
import json

#-----------------------------------------------------------------------------
# Static file paths
#-----------------------------------------------------------------------------

# Allow image loading
@route('/img/<picture:path>')
def serve_pictures(picture):
    '''
        serve_pictures

        Serves images from static/img/

        :: picture :: A path to the requested picture

        Returns a static file object containing the requested picture
    '''
    return static_file(picture, root='static/img/')

#-----------------------------------------------------------------------------

# Allow CSS
@route('/css/<css:path>')
def serve_css(css):
    '''
        serve_css

        Serves css from static/css/

        :: css :: A path to the requested css

        Returns a static file object containing the requested css
    '''
    return static_file(css, root='static/css/')

#-----------------------------------------------------------------------------

# Allow javascript
@route('/js/<js:path>')
def serve_js(js):
    '''
        serve_js

        Serves js from static/js/

        :: js :: A path to the requested javascript

        Returns a static file object containing the requested javascript
    '''
    return static_file(js, root='static/js/')

#-----------------------------------------------------------------------------
# Index Page
#-----------------------------------------------------------------------------

# Redirect to login
# @get('/')
@get('/home')
def get_index():
    '''
        get_index

        Serves the index page
    '''
    return model.index()

#-----------------------------------------------------------------------------
# Login Page
#-----------------------------------------------------------------------------

# Display the login page
@get('/')
@get('/login')
def get_login_controller():
    '''
        get_login

        Serves the login page
    '''
    return model.login_form()

#-----------------------------------------------------------------------------

# Attempt the login
@post('/login')
def post_login():
    '''
        post_login

        Handles login attempts
        Expects a form containing 'username' and 'password' fields
    '''

    # Handle the form processing
    username = request.forms.get('username')
    password = request.forms.get('password')

    if username and password:
        retPage = model.login_check(username, password)
        if retPage[0]:
            # print("Valid username or password")
            response.set_cookie("currentUser", username)
            redirect('/msg_window')
        else:
            # print("Invalid username or password")
            return retPage[1]

    # Call the appropriate method
    return model.login_form()

#-----------------------------------------------------------------------------
# Register
#-----------------------------------------------------------------------------

# Display the login page
@get('/register')
def get_register_controller():
    '''
        get_login

        Serves the login page
    '''
    return model.register_form()

#-----------------------------------------------------------------------------

# Attempt the register
@post('/register')
def post_register():
    '''
        post_register

        Handles register attempts
        Expects a form containing 'username', 'password' and 'reentered' fields
    '''

    # Handle the form processing
    # username = request.forms.get('username')
    # password = request.forms.get('password')
    # reentered = request.forms.get('reentered')

    registerForm = request.json
    # print(registerForm)
    # print(registerForm.get("username"))
    username = registerForm["username"]
    hashed = registerForm["hashed"]
    salt = registerForm["salt"]

    print("user: " + username)
    print("hashed: " + hashed)
    print("salt: " + salt)


    if username and hashed:
        retVals = model.register_new(username, hashed, salt)

        returnValues = [{"error": retVals[0]}]
        # returnValues = [{"user": username}]
        response.headers['Content-Type'] = 'application/json'
        return json.dumps({'error': retVals[0]})
        # return retVals[1]

    # Call the appropriate method
    # return model.register_form()
    return

@post('/add_user')
def add_user():
    # print(request.json)
    userDetails = request.json;
    model.store_public_key(userDetails["username"], userDetails["publicKey"])

    response.headers['Content-Type'] = 'application/json'
    return json.dumps({'status': "success"})

#-----------------------------------------------------------------------------
# Message Window Page
#-----------------------------------------------------------------------------

@get('/msg_window')
def get_msg_window():
    '''
        get_friends

        Serves the friends page
    '''
    return model.msg_window()

#-----------------------------------------------------------------------------

# Attempt the login
@post('/msg_window')
def post_msg_window():
    '''
        post_msg_window

        Handles user sending messages
        Expects a form containing 'message' field
    '''

    # Handle the form processing
    message = request.forms.get('message')

    # Call the appropriate method
    return model.msg_window()


@post('/add_sessionkeysEntry')
def add_sessionkeysEntry():
    # print(request.json)
    sessionKeys = request.json

    sessionKeysList = []
    for k, v in sessionKeys.items():
        temp = [k, v]
        sessionKeysList.append(temp)

    model.store_session_key(sessionKeysList[0][0], sessionKeysList[0][1], sessionKeysList[1][0], sessionKeysList[1][1])

    response.headers['Content-Type'] = 'application/json'
    return json.dumps({'status': "success"})

#-----------------------------------------------------------------------------
# Database Callers
#-----------------------------------------------------------------------------
@post('/get_public_key')
def get_public_key():
    # print(request.json)
    # print(userJson["username"])
    userJson = request.json;
    publicKey = model.get_public_key(userJson["username"])
    # print(retVal)

    if (publicKey != None):
        response.headers['Content-Type'] = 'application/json'
        return json.dumps({'public_key': publicKey})
    else:
        response.headers['Content-Type'] = 'application/json'
        return json.dumps({'error': "Username not found"})


@post('/get_session_key')
def get_session_key():
    # print(request.json)
    # print(userJson["username"])
    userJson = request.json;
    sessionKey = model.get_session_key(userJson["sender"], userJson["recipient"])
    # print(sessionKey)

    if (sessionKey != None):
        response.headers['Content-Type'] = 'application/json'
        return json.dumps({'session_key': sessionKey})
    else:
        response.headers['Content-Type'] = 'application/json'
        return json.dumps({'error': "Username not found"})



#-----------------------------------------------------------------------------
# About Page
#-----------------------------------------------------------------------------

@get('/about')
def get_about():
    '''
        get_about

        Serves the about page
    '''
    return model.about()

#-----------------------------------------------------------------------------
# Miscellaneous Helpers
#-----------------------------------------------------------------------------

# Help with debugging
@post('/debug/<cmd:path>')
def post_debug(cmd):
    return model.debug(cmd)

#-----------------------------------------------------------------------------

# 404 errors, use the same trick for other types of errors
@error(404)
def error(error):
    return model.handle_errors(error)
