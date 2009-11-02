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
sql = """
create table if not exists sessions (
session_id char(128) unique not null,
atime timestamp not null default current_timestamp,
data text);
"""
cur.execute(sql)
cur.close()
del cur

def db_create():
	cur = db._db_cursor()
	sql = """create table if not exists user 
	(uid int primary key, name,password,email,unique(name))"""
	cur.execute(sql)
	sql = """create table if not exists properties (
	pid int primary key, uid int, ptype int,
	ctime timestamp NOT NULL default current_timestamp,
	name varchar(64)
	)
	"""
	cur.execute(sql)
	sql = """create table if not exists properties_type (
		ptype int,
		desc varchar(64), unique(desc)
	)
	"""
	cur.execute(sql)
	sql = """insert into properties_type (ptype,desc) values
	(1, 'Starter Forest')
	"""
	cur.execute(sql)
	sql = """insert into properties_type (desc) values
	(2, 'Starter Cave')
	"""
	cur.execute(sql)
	cur.close()
	del cur

def make_hash(password):
	s = hashlib.sha1()
	s.update(password)
	s.update(SECRET)
	return s.hexdigest()

def make_supersecret(username,hashed_password):
	s = hashlib.sha1()
	s.update(username)
	s.update(hashed_password)
	s.update(SUPER_SECRET)
	return s.hexdigest()

def db_create_new_user(username, password,email):
	cur = db._db_cursor()
	sql = """insert into user (name,password,email)
	values (?,?,?)"""
	cur = db._db_cursor()
	hashed_password = make_hash(password)
	try:
		cur.execute(sql,(username,hashed_password,email))
	except sqlite3.IntegrityError:
		cur.close()
		return False	
	sql = "select uid from user where name=?"
	cur.execute(sql)
	(db_uid,) = cur.fetchone()
	sql = """insert into properties (uid,)
	values (?,)
	"""
	cur.execute(sql)
	cur.close()
	db.ctx.commit()
	return True

def db_hash_valid(username, hashvalue):
	cur = db._db_cursor()
	sql = """select count(*) from
	user where name=? and password=?"""
	cur.execute(sql, (username,hashvalue))
	(counter,) = cur.fetchone()
	cur.close()
	if counter == 1:
		return True
	return False

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

def check_for_cookies():
	log.debug("checking for cookie name")
	name = web.cookies().get("name")
	log.debug("got value for cookie name " + str(name))
	if name is None:
		return (False,None,None,None)
	data = name.split(":")
	username = data[0]
	hashed_password = data[1]
	super_secret = data[2]
	return (True,username,hashed_password,super_secret)

urls = ("^/$", "MainPage",
	"^/login$", "LoginPage",
	"^/loginerr$", "LoginErrPage",
	"^/logout$", "LogoutPage",
	"^/bets$", "BetsPage",
	"^/reg$", "RegPage",
	"^/regerr$", "RegErrPage",
	"^/passwordreset$", "PasswordResetPage", 
	"^/properties$", "PropertiesPage", 
	"^/createdb$", "CreateDBPage",)

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

class CreateDBPage:
	def GET(self):
		db_create()
		t = Template(file="./html/createdb.html")
		return str(t)

class PropertiesPage:
	def GET(self):
		t = Template(file="./html/properties.html")
		return str(t)

class PasswordResetPage:
	def GET(self):
		t = Template(file="./html/passwordreset.html")
		return str(t)

class BetsPage:
	def GET(self):
		t = Template(file="./html/bets.html")
		t.valid_user = session.valid_user
		t.name = session.name
		return str(t)

class LogoutPage:
	def GET(self):
		session.kill()
		web.setcookie("name", "", 0)
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

		result = db_create_new_user(inp.username,
			inp.password, inp.email)
		if result:
			session.valid_user = True
			session.name = inp.username
		else:
			# TODO: you really did not get reg'd
			pass
		raise web.seeother("/")	

class LoginErrPage:
	def GET(self):
		t = Template(file="./html/loginerr.html")
		return str(t)

class LoginPage:
	def POST(self):
		inp = web.input()

		# verify input from web form
		valid_user = db_user_valid(inp.username,
			inp.password)
	
		# remember it in session object (good or bad does not matter)
		session.valid_user = valid_user

		# if we have a validated user
		if valid_user:
			log.debug("this is a valid user " + inp.username)
			# save the username
			session.name = inp.username
	
			# TODO write cookie here!
			# 3600 = hour * 24 = day * 14 = 14 days
			hashed_password = make_hash(inp.password)
			log.debug("hashed password " + hashed_password)

			super_secret = make_supersecret(inp.username,hashed_password)
			log.debug("super secret " + super_secret)
			value = "%s:%s:%s" % (inp.username, make_hash(inp.password),
				super_secret)
			log.debug("value " + value)
			web.setcookie("name", value, 3600*24*14)
		else:
			raise web.seeother("/loginerr")

		# either way go back to the front page
		raise web.seeother("/")

class MainPage:
	def GET(self):
		log.debug("MainPage.GET begin")
		(c_valid_cookie, c_name, c_password, c_supersecret) = check_for_cookies()
		log.debug("cookie: " + str(c_valid_cookie) + " " + str(c_name) + " " + 
			str(c_password))
		t = Template(file="./html/index.html")
		t.ctx=web.webapi.ctx
		if c_valid_cookie:
			t.valid_user = True
			t.name = c_name
		else:
			t.valid_user = session.valid_user
			t.name = session.name

		log.debug("MainPage.GET end")
		return str(t)

if __name__ == "__main__":
	app.run()
