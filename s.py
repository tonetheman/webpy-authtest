import web, sqlite3, hashlib,re
import logging as log
from Cheetah.Template import Template

log.basicConfig(filename="./dbg.log",level=log.DEBUG)

web.config.debug = False
NAME_PAT = re.compile("^[a-zA-Z0-9_]+$")
E_INVALID_NAME = """The username you tried to register is invalid.
the only valid usernames are alpha or numbers or underscores.
"""

SECRET="goofy goober goo"
SUPER_SECRET="goo goo choo"
db = web.database(dbn="sqlite", db="./weather.db")
log.debug("db opened")
cur = db._db_cursor()
sql = """create table if not exists user 
(uid int primary key, name,password,email,unique(name))"""
cur.execute(sql)
sql = """
create table if not exists sessions (
    session_id char(128) UNIQUE NOT NULL,
    atime timestamp NOT NULL default current_timestamp,
    data text
);
"""
cur.execute(sql)
cur.close()
del cur

def check_for_cookies():
	log.debug("checking for cookie name")
	name = web.cookies().get("name")
	log.debug("got value for cookie name " + str(name))
	if name is None:
		return (False,None)
	return (False,None)

def make_hash(password):
	s = hashlib.sha1()
	s.update(password)
	s.update(SECRET)
	return s.hexdigest()

def db_create_new_user(username, password,email):
	cur = db._db_cursor()
	sql = """insert into user (name,password,email)
	values (?,?,?)"""
	cur = db._db_cursor()
	hashed_password = make_hash(password)
	cur.execute(sql,(username,hashed_password,email))
	cur.close()
	db.ctx.commit()

def db_user_valid(username, password):
	cur = db._db_cursor()
	sql = """select uid,name,password from 
	user where name=?"""
	cur = db._db_cursor()
	cur.execute(sql,(username,))
	data = cur.fetchone()
	cur.close()

	if data is None:
		return False
	(db_uid,db_username,db_password) = data
	del cur
	hashed_password = make_hash(password)
	if db_username == username and db_password == hashed_password:
		return True
	return False

urls = ("^/$", "MainPage",
	"^/login$", "LoginPage",
	"^/logout$", "LogoutPage",
	"^/bets$", "BetsPage",
	"^/reg$", "RegPage",
	"^/regerr$", "RegErrPage" )
app = web.application(urls,globals())
"""
session = web.session.Session(app,
	web.session.DiskStore("sessions"),
	initializer={"valid_user":False, "name" : None})
"""
session = web.session.Session(app,
	web.session.DBStore(db, "sessions"),
	initializer={"valid_user":False,"name":None})
log.debug("session started")

class BetsPage:
	def GET(self):
		t = Template(file="./html/bets.html")
		t.valid_user = session.valid_user
		t.name = session.name
		return str(t)

class LogoutPage:
	def GET(self):
		session.kill()
		raise web.seeother("/")

class RegErrPage:
	def GET(self):
		t = Template(file="./html/regerr.html")
		t.errstr = session.errstr
		return str(t)

class RegPage:
	def GET(self):
		t = Template(file="./html/reg.html")
		return str(t)
	def POST(self):
		inp = web.input()
		if not NAME_PAT.match(inp.username):
			session.errstr = E_INVALID_NAME
			raise web.seeother("/regerr")

		db_create_new_user(inp.username,
			inp.password, inp.email)
		session.valid_user = True
		session.name = inp.username
		raise web.seeother("/")	

class LoginPage:
	def POST(self):
		inp = web.input()
		valid_user = db_user_valid(inp.username,
			inp.password)
		session.valid_user = valid_user
		if valid_user:
			session.name = inp.username
		raise web.seeother("/")

class MainPage:
	def GET(self):
		log.debug("MainPage.GET begin")
		(c_valid_user, c_name) = check_for_cookies()
		t = Template(file="./html/index.html")
		t.ctx=web.webapi.ctx
		if c_valid_user:
			t.valid_user = True
			t.name = c_name
		else:
			t.valid_user = session.valid_user
			t.name = session.name

		log.debug("MainPage.GET end")
		return str(t)

if __name__ == "__main__":
	app.run()
