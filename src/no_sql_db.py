# This file provides a very simple "no sql database using python dictionaries"
# If you don't know SQL then you might consider something like this for this course
# We're not using a class here as we're roughly expecting this to be a singleton

# If you need to multithread this, a cheap and easy way is to stick it on its own bottle server on a different port
# Write a few dispatch methods and add routes

# A heads up, this code is for demonstration purposes; you might want to modify it for your own needs
# Currently it does basic insertions and lookups
from inspect import formatargvalues
import os

cur_path = os.path.dirname(__file__)
user_db_path = os.path.join(cur_path, 'db/user_database.txt')
pubkey_db_path = os.path.join(cur_path, 'db/public_key_database.txt')
sesskey_db_path = os.path.join(cur_path, 'db/session_key_database.txt')
messages_db_path = os.path.join(cur_path, 'db/messages.txt')
forums_db_path = os.path.join(cur_path, 'db/forums.txt')
posts_db_path = os.path.join(cur_path, 'db/posts.txt')
comments_db_path = os.path.join(cur_path, 'db/comments.txt')
tags_db_path = os.path.join(cur_path, 'db/tags.txt')
post_tags_db_path = os.path.join(cur_path, 'db/post_tags.txt')
forum_subscriptions_db_path = os.path.join(cur_path, 'db/forum_subscriptions.txt')

class Table():
    def __init__(self, table_name, db_path, *table_fields):
        self.name = table_name
        self.db_path = db_path
        self.fields = table_fields
        self.entries = []

    def load_entries(self):

        with open(self.db_path, 'r') as user_db:
            lines = [line.rstrip() for line in user_db]

            # Strips the newline character
            for details in lines:
                detailsArr = details.split(",")
                self.entries.append(detailsArr)

    def create_entry(self, data):
        '''
        Inserts an entry in the table
        Doesn't do any type checking
        '''

        # Bare minimum, we'll check the number of fields
        if len(data) != len(self.fields):
            raise ValueError('Wrong number of fields for table')

        with open(self.db_path, 'a') as table_db:
            table_db.write(",".join([str(field) for field in data]) + "\n")

        self.entries.append(data)
        return

    def search_table(self, target_field_name, target_value):
        '''
            Search the table given a field name and a target value
            Returns the first entry found that matches
        '''

        # Lazy search for matching entries
        for entry in self.entries:
            for field_name, value in zip(self.fields, entry):
                if target_field_name == field_name and target_value == value:
                    return entry

        # Nothing Found
        return None

    def get_entries(self, target_field_name, target_value):
        '''
            Search the table for given a field name and a target value
            returns the entries found that match.
        '''
        entries = []
        for entry in self.entries:
            for field_name, value in zip(self.fields, entry):
                if target_field_name == field_name and target_value == value:
                    entries.append(entry)

        return entries

    def override_existing_entry(self, target_field_name, target_value, data):
        '''
            Search the table for given a field name and a target value
            returns the entries found that match.
        '''

        success = False
        for entry in self.entries:
            for field_name, value in zip(self.fields, entry):
                if target_field_name == field_name and target_value == value:
                    entry = data
                    self.save_table()
                    return True        

        return False

    def save_table(self):
        '''
            Manual save of whole table
        :return:
        '''
        with open(self.db_path, 'w') as user_db:
            for entry in self.entries:
                user_db.write(",".join([str(field) for field in entry]) + "\n")

    def print_table(self):
        '''
            Prints table entries
        '''
        for entry in self.entries:
            print(entry)




class DB():
    '''
    This is a singleton class that handles all the tables
    You'll probably want to extend this with features like multiple lookups, and deletion
    A method to write to and load from file might also be useful for your purposes
    '''
    def __init__(self):
        self.tables = {}

        # Setup your tables
        self.add_table('users', user_db_path,"username", "hash_string", "salt", "friends")
        self.add_table('public_keys', pubkey_db_path,'username', 'public_key')
        self.add_table('session_keys', sesskey_db_path,'A_username', 'enc_Apub_sk', 'B_username', 'enc_Bpub_sk', "hmac_key",'iv')
        self.add_table('messages', messages_db_path,'sender', 'recipient', 'enc_msg_ts', 'mac_enc_msg_ts')
        self.add_table('forums', forums_db_path, "forum_id", "name", "description", "creator")
        self.add_table('posts', posts_db_path, 'post_id', 'forum_id', 'author', 'title', 'body', 'timestamp')
        self.add_table('comments', comments_db_path, 'post_id', 'author', 'body', 'timestamp')
        self.add_table('tags', tags_db_path, 'tag')
        self.add_table('post_tags', post_tags_db_path, 'post_id', 'tag')
        self.add_table('forum_subscriptions', forum_subscriptions_db_path, 'subscriber', 'forum_id')
        # Loads user database
        self.load_data_table('forum_subscriptions')
        self.load_data_table('tags')
        self.load_data_table('post_tags')
        self.load_data_table('forums')
        self.load_data_table('posts')
        self.load_data_table('comments')
        self.load_data_table("users")
        self.load_data_table('public_keys')
        self.load_data_table('session_keys')
        self.load_data_table('messages')
        
        return

    def add_table(self, table_name, *table_fields):
        '''
            Adds a table to the database
        '''
        table = Table(table_name, *table_fields)
        self.tables[table_name] = table

        return


    def search_table(self, table_name, target_field_name, target_value):
        '''
            Calls the search table method on an appropriate table
        '''
        return self.tables[table_name].search_table(target_field_name, target_value)

    def get_entries(self, table_name, target_field_name, target_value):
       '''
            calls the get entries method on the appropriate table
       '''
       return self.tables[table_name].get_entries(target_field_name, target_value)

    def create_table_entry(self, table_name, data):
        '''
            Calls the create entry method on the appropriate table
        '''
        return self.tables[table_name].create_entry(data)

    def override_existing_entry(self, table_name, target_field_name, target_value, data):
        '''
            Calls the edit entry method on the appropriate table
        '''
        return self.tables[table_name].override_existing_entry(target_field_name, target_value, data)        

    def print_table(self, table_name):
        self.tables[table_name].print_table()

    def save_table(self, table_name):
        self.tables[table_name].save_table()

    def load_data_table(self, table_name):
        self.tables[table_name].load_entries()

# Our global database
# Invoke this as needed
database = DB()
