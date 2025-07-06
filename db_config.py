import pymysql
def get_db_connection():
    connection = pymysql.connect(host='localhost',
                                 user='root', # MySQL 사용자 이름
                                 password='P@ssw0rd!', # MySQL 비밀번호
                                 database='board_db',
                                 cursorclass=pymysql.cursors.DictCursor)
    return connection