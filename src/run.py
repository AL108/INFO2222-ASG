'''
    This is a file that configures how your server runs
    You may eventually wish to have your own explicit config file
    that this reads from.

    For now this should be sufficient.

    Keep it clean and keep it simple, you're going to have
    Up to 5 people running around breaking this constantly
    If it's all in one file, then things are going to be hard to fix

    If in doubt, `import this`
'''

#-----------------------------------------------------------------------------
import os
import sys
from bottle import run

#-----------------------------------------------------------------------------
# You may eventually wish to put these in their own directories and then load
# Each file separately

# For the template, we will keep them together

import model
import view
import controller

#-----------------------------------------------------------------------------

# It might be a good idea to move the following settings to a config file and then load them
# Change this to your IP address or 0.0.0.0 when actually hosting
import no_sql_db

host = '127.0.0.1'

# Test port, change to the appropriate port to host
port = 8081

# Turn this off for production
debug = True

def run_server(keyfilepath, certfilepath):
    '''
        run_server
        Runs a bottle server
    '''
    run(host=host, port=port,debug=debug, keyfile=keyfilepath, certfile=certfilepath, server="gunicorn")


keyfilepath = sys.argv[1]
certfilepath = sys.argv[2]
run_server(keyfilepath, certfilepath)
