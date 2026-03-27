import psycopg2

def get_connection():
    return psycopg2.connect(
        host="localhost",
        database="john_db",
        user="postgres",
        password="1234"
    )
