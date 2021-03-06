'''
    This file will handle our typical Bottle requests and responses
    You should not have anything beyond basic page loads, handling forms and
    maybe some simple program logic
'''

from bottle import route, get, post, error, request, static_file, response, redirect

import model
import json
import time

lastMessageTime = 0

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
@get('/')
@get('/home')
def get_index():
    '''
        get_index

        Serves the index page
    '''
    return model.home()

#-----------------------------------------------------------------------------
# Login Page
#-----------------------------------------------------------------------------

# Display the login page
# @get('/')
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
    # username = request.forms.get('username')
    # password = request.forms.get('password')

    loginForm = request.json

    username = loginForm["username"]
    password = loginForm["password"]

    if username and password:
        retPage = model.login_check(username, password)
        if retPage[0]:
            response.set_cookie("currentUser", username)

            response.headers['Content-Type'] = 'application/json'
            return json.dumps({'success': "Login successful"})
            # redirect('/msg_window')
        else:
            response.headers['Content-Type'] = 'application/json'
            return json.dumps({'failed': "Invalid username or password"})

    # Call the appropriate method
    redirect('/login')

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

@post('/subscribe')
def post_subscribe():
    '''

    '''
    # Handle the form processing
    req = request.json
    forum_id = req["forum_id"]
    subscriber = req["subscriber"]
    ret = -1
    if forum_id:
       ret = model.subscribe(subscriber, forum_id)
    # Call the appropriate method
    return json.dumps({'ret': ret})

@post('/get_posts')
def get_posts():
    print(request.json)
    forum_id = request.json['forum_id']
    postsList = model.get_posts(forum_id)
    if postsList:
        response.headers['Content-Type'] = 'application/json'
        return json.dumps({'posts': postsList})
    return json.dumps({'error': "did not find anything"})

@post('/forum_exists')
def post_forum_exists():
    '''
        returns whether the forum exists
    '''
    forum_id = request.json["forum_id"]
    ret = False
    if forum_id:
        ret = model.forum_exists(forum_id)
    return json.dumps({'forum_exists': ret})

@post('/register')
def post_register():
    '''
        post_register
        Handles register attempts
        Expects a form containing 'username', 'password' and 'reentered' fields
    '''

    # Handle the form processing
    registerForm = request.json

    username = registerForm["username"]
    hashed = registerForm["hashed"]
    salt = registerForm["salt"]

    if username and hashed:
        retVals = model.register_new(username, hashed, salt)

        returnValues = [{"error": retVals[0]}]
        response.headers['Content-Type'] = 'application/json'
        return json.dumps({'error': retVals[0]})

    # Call the appropriate method
    return



@post('/add_user')
def add_user():
    userDetails = request.json;
    model.store_public_key(userDetails["username"], userDetails["publicKey"])

    response.headers['Content-Type'] = 'application/json'
    return json.dumps({'status': "success"})

#-----------------------------------------------------------------------------
# Landing / Home Page
#-----------------------------------------------------------------------------
@get('/home')
def get_home():
    '''
        get_home

        Serves the home page
    '''
    return model.home()

#-----------------------------------------------------------------------------
# forum page
#-----------------------------------------------------------------------------
@get('/forums')
def get_forums():
    return model.forums()

@post('/get_tags')
def get_tags():
    post_id = request.json["post_id"]
    tagsList = model.get_tags(post_id)
    print("tgslist", tagsList)
    if tagsList:
        response.headers['Content-Type'] = 'application/json'
        return json.dumps({'tags': tagsList})
    return json.dumps({'error': "did not find anything"})

@post('/create_forum')
def create_forum():
    req = request.json
    creator = req['creator']
    name = req['forumName']
    desc = req['desc']
    forum_id = model.create_forum(creator, name, desc)
    if forum_id:
        return json.dumps({'forum_id': forum_id})
    return json.dumps({'error': "forum create failed"})

@post('/create_post')
def create_post():
    req = request.json
    creator = req['creator']
    title = req['title']
    body = req['body']
    tag = req['tag']
    forum_id = req['forum_id']
    post_id = model.create_post(creator, title, body, tag, forum_id)
    if post_id:
        return json.dumps({'post_id': post_id})
    return json.dumps({'error': "post create failed"})

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
    sessionKeys = request.json

    hmacKeyString = sessionKeys["hmacKeyString"]
    iv = sessionKeys["iv"]

    sessionKeysList = []
    for k, v in sessionKeys.items():
        temp = [k, v]
        sessionKeysList.append(temp)

    model.store_session_key(sessionKeysList[0][0], sessionKeysList[0][1], sessionKeysList[1][0], sessionKeysList[1][1], hmacKeyString, iv)

    response.headers['Content-Type'] = 'application/json'
    return json.dumps({'status': "success"})

@post('/post_getMessages')
def post_getMessages():
    recipientObj = request.json
    recipient = recipientObj["recipient"]

    messagesList = model.get_messages(recipient)

    if messagesList:
        response.headers['Content-Type'] = 'application/json'
        return json.dumps({'messages': messagesList})
    return json.dumps({'error': "did not find anything"})

@post('/post_getComments')
def post_getComments():
    post_id = request.json['post_id']
    commentsList = model.get_comments(post_id)
    if commentsList:
        response.headers['Content-Type'] = 'application/json'
        return json.dumps({'comments': commentsList})
    return json.dumps({'error': "did not find anything"})

@post('/post_getForums')
def post_getForums():
    user_logged_in = request.json["user_logged_in"]
    id_list = model.get_forums(user_logged_in)

    if id_list:
        response.headers['Content-Type'] = 'application/json'
        return json.dumps({'forum_ids': id_list})

    return json.dumps({'error': "did not find anything"})

@post('/post_getForumName')
def post_getForumName():
    forum_id = request.json['forum_id']
    forum_name = model.get_forum_name(forum_id)
    if forum_name:
        response.headers['Content-Type'] = 'application/json'
        return json.dumps({'forum_name': forum_name})
    return json.dumps({'error': "hmm thats weird"})

@post('/post_getForumDesc')
def post_getForumDesc():
    forum_id = request.json['forum_id']
    forum_desc = model.get_forum_desc(forum_id)
    if forum_desc:
        response.headers['Content-Type'] = 'application/json'
        return json.dumps({'forum_desc': forum_desc})
    return json.dumps({'error': "hmm thats weird"})

@post('/post_getForumAdmin')
def post_getForumAdmin():
    forum_id = request.json['forum_id']
    forum_admin = model.get_forum_admin(forum_id)
    if forum_admin:
        response.headers['Content-Type'] = 'application/json'
        return json.dumps({'forum_admin': forum_admin})
    return json.dumps({'error': "hmm thats weird"})

@post('/post_newMessage')
def post_newMessage():
    testDelay = 10000
    global lastMessageTime
    if (time.time() * 1000) <= lastMessageTime + testDelay:
        print("Slow down!")
        return

    lastMessageTime = time.time() * 1000
    # -----------------------------------------

    newMessageDetails = request.json

    sender = newMessageDetails["sender"]
    recipient = newMessageDetails["recipient"]
    enc_msg = newMessageDetails["enc_msg"]
    hmacSig = newMessageDetails["hmacSig"]

    model.store_message(sender, recipient, enc_msg, hmacSig);

    response.headers['Content-Type'] = 'application/json'
    return json.dumps({'status': "success"})

#-----------------------------------------------------------------------------
# Database Callers
#-----------------------------------------------------------------------------
@post('/get_public_key')
def get_public_key():
    userJson = request.json
    publicKey = model.get_public_key(userJson["username"])

    if (publicKey != None):
        response.headers['Content-Type'] = 'application/json'
        return json.dumps({'public_key': publicKey})
    else:
        response.headers['Content-Type'] = 'application/json'
        return json.dumps({'error': "Username not found"})


@post('/get_session_key')
def get_session_key():
    userJson = request.json
    sessionKeyEntry = model.get_session_key(userJson["sender"], userJson["recipient"])

    if (sessionKeyEntry != None):
        response.headers['Content-Type'] = 'application/json'
        return json.dumps({'sessionKeyEntry': sessionKeyEntry})
    else:
        response.headers['Content-Type'] = 'application/json'
        return json.dumps({'error': "Username not found"})

@post('/add_friend')
def add_friend():
    userJson = request.json
    addFriendStatus = model.add_friend(userJson["username"], userJson["friend"])

    if addFriendStatus:
        response.headers['Content-Type'] = 'application/json'
        return json.dumps({'Status': "Success"})
    else:
        response.headers['Content-Type'] = 'application/json'
        return json.dumps({'Status': "Failed"})
    
@post('/add_comment')
def add_comment():
    req = request.json
    model.add_comment(req['post_id'], req['author'], req['comment'], str(int(time.time()*1000.0)))

@post('/get_friends_list')
def get_friends_list():
    userJson = request.json
    friendsList = model.get_friends_list(userJson["username"])

    if (friendsList != None):
        response.headers['Content-Type'] = 'application/json'
        return json.dumps({'friendsList': friendsList})
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
