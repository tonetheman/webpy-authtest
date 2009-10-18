import web, sqlite3, hashlib
from Cheetah.Template import Template
web.config.debug = False

SECRET="goofy goober goo"
db = web.database(dbn="sqlite", db="./weather.db")
cur = db._db_cursor()
sql = """create table if not exists user 
(uid int primary key, name,password,email,unique(name))"""
cur.execute(sql)
cur.close()
del cur

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
	"^/reg$", "RegPage" )
app = web.application(urls,globals())
session = web.session.Session(app,
	web.session.DiskStore("sessions"),
	initializer={"valid_user":False, "name" : None})

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

class RegPage:
	def GET(self):
		t = Template(file="./html/reg.html")
		return str(t)
	def POST(self):
		inp = web.input()
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
		t = Template(file="./html/index.html")
		t.ctx=web.webapi.ctx
		t.valid_user = False
		if session.has_key("valid_user"):
			if session.valid_user:
				t.valid_user = True
				t.name = session.name

		return str(t)

if __name__ == "__main__":
	app.run()
