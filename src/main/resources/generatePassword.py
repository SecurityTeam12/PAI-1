import random
import string

def generate_password(length=12):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(characters) for _ in range(length))

def generate_sql_insert(num_users=5, filename='data.sql'):
    sql_statements = []
    for i in range(1, num_users + 1):
        username = f'user{i}'
        password = generate_password()
        sql_statements.append(f"INSERT INTO users (id, username, password) VALUES ({i}, '{username}', '{password}');")
    with open(filename, 'w') as file:
        file.write('\n'.join(sql_statements))

if __name__ == "__main__":
    generate_sql_insert(5)
    print(generate_password())
