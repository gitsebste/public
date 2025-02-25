import sqlite3

def execute_query(user_input):
    connection = sqlite3.connect('example.db')
    cursor = connection.cursor()
    query = "SELECT * FROM users WHERE name = '" + user_input + "'"
    cursor.execute(query)
    results = cursor.fetchall()
    for row in results:
        print(row)
    connection.close()
