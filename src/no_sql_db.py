# This file provides a very simple "no sql database using python dictionaries"
# If you don't know SQL then you might consider something like this for this course
# We're not using a class here as we're roughly expecting this to be a singleton

# If you need to multithread this, a cheap and easy way is to stick it on its own bottle server on a different port
# Write a few dispatch methods and add routes

# A heads up, this code is for demonstration purposes; you might want to modify it for your own needs
# Currently it does basic insertions and lookups
import os

db_path = 'db/user_database.txt'
cur_path = os.path.dirname(__file__)
user_db_path = os.path.join(cur_path, db_path)

class Table():
    def __init__(self, table_name, *table_fields):
        self.entries = []
        self.fields = table_fields
        self.name = table_name

    def load_entries(self, user_db_path):

        with open(user_db_path, 'r') as user_db:
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

        with open(user_db_path, 'a') as user_db:
            user_db.write(",".join([str(field) for field in data]) + "\n")

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

    def save_table(self):
        '''
            Manual save of whole table
        :return:
        '''
        with open(user_db_path, 'w') as user_db:
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
        self.add_table('users',"username", "hash_string", "salt")

        # Loads user database
        self.load_data_table("users", user_db_path)

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

    def create_table_entry(self, table_name, data):
        '''
            Calls the create entry method on the appropriate table
        '''
        return self.tables[table_name].create_entry(data)

    def print_table(self, table_name):
        self.tables[table_name].print_table()

    def save_table(self, table_name):
        self.tables[table_name].save_table()

    def load_data_table(self, table_name, db_path):
        self.tables[table_name].load_entries(db_path)

# Our global database
# Invoke this as needed
database = DB()
