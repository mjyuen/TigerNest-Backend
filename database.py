from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token,
    get_jwt_identity
)
import os
import hashlib
import json
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
import time
import jwt

from flask_heroku import Heroku

basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)

# Setup the Flask-JWT-Extended extension
app.config['JWT_SECRET_KEY'] = 'super-secret'  # Change this!
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = 60 * 60 * 24 # expire after 1 day
jwt_flask = JWTManager(app)

bcrypt = Bcrypt(app)
CORS(app)
#postgres://vhhabiabmrdtya:d2d626af16f4894a2a656de2ca8158f4414687b9b84ea08f801c2c07d774c6b8@ec2-54-243-241-62.compute-1.amazonaws.com:5432/d9d1mlh0cjs2lf

#app.config['SQLALCHEMY_DATABASE_URI'] = "postgres://vhhabiabmrdtya:d2d626af16f4894a2a656de2ca8158f4414687b9b84ea08f801c2c07d774c6b8@ec2-54-243-241-62.compute-1.amazonaws.com:5432/d9d1mlh0cjs2lf"

#app.config['SQLALCHEMY_DATABASE_URI'] = "postgresql://localhost/tigernest"
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ['DATABASE_URL']
#app.config['SQLALCHEMY_DATABASE_URI'] = os.environ['DATABASE_URL']

heroku = Heroku(app)
db = SQLAlchemy(app)
ma = Marshmallow(app)


@app.route("/getRegCode", methods = ["GET"])
def get_code():
	result = {"regCode": "2sdi319230d8208sd"}
	return jsonify(result)

class EventOrganizer(db.Model):
	event_organizer_id = db.Column(db.Integer, primary_key = True)
	netid = db.Column(db.Unicode, unique = True)
	firstname = db.Column(db.Unicode, unique = False)
	lastname = db.Column(db.Unicode, unique = False)
	email = db.Column(db.Unicode, unique = False)
	password = db.Column(db.Unicode, unique = False)
	campus_organizations = db.Column(db.JSON, unique = False)

	def __init__(self, netid, firstname, lastname, email, password, campus_organizations):
		self.netid = netid
		self.firstname = firstname
		self.lastname = lastname
		self.email = email
		self.password = password
		self.campus_organizations = campus_organizations


class EventOrganizerSchema(ma.Schema):
	class Meta:
		fields = ('event_organizer_id', 'netid', 'firstname', 'lastname', 'email', 'password', 'campus_organizations')

event_organizer_schema = EventOrganizerSchema()
event_organizers_schema = EventOrganizerSchema(many = True)

# Endpoint to add new event organizer
@app.route("/event_organizer", methods=["POST"])
def event_organizer_add():
	netid = request.json['netid']
	firstname = request.json['firstname']
	lastname = request.json['lastname']
	email = request.json['email']
	password = request.json['password']
	campus_organizations = request.json['campus_organizations']

	new_event_organizer = EventOrganizer(netid, firstname, lastname, email, password, campus_organizations)
	db.session.add(new_event_organizer)
	db.session.commit()
	return event_organizer_schema.jsonify(new_event_organizer)

# Endpoint to retrieve existing event organizer from the database
@app.route("/event_organizer/<event_organizer_id>", methods=["GET"])
def event_organizer_get(event_organizer_id):
	event_organizer = EventOrganizer.query.get(event_organizer_id)
	return event_organizer_schema.jsonify(event_organizer)

@app.route("/event_organizer/email/<email>", methods=["GET"])
def event_organizer_get_email(email):
	event_organizer = EventOrganizer.query.filter_by(email=email).first()
	return event_organizer_schema.jsonify(event_organizer)

@app.route("/event_organizer/netidVerify/<netid>", methods=["GET"])
def event_organizer_verify_netid(netid):
	event_organizer = EventOrganizer.query.filter_by(netid=netid).first()
	#return event_organizer_schema.jsonify(event_organizer)
	#return event_organizer_schema.jsonify(event_organizer)
	return event_organizer_schema.jsonify(event_organizer)


@app.route("/event_organizer/getCount", methods=["GET"])
def event_organizer_get_count():
	count = session.query(EventOrganizer.netid).count()
	return count
#------------------------------------------------------------------------------------------
class Event(db.Model):
	event_id = db.Column(db.Integer, primary_key = True)
	name = db.Column(db.Unicode, unique = False)
	start_date = db.Column(db.Unicode, unique = False)
	start_time = db.Column(db.Unicode, unique = False)
	end_date = db.Column(db.Unicode, unique = False)
	end_time = db.Column(db.Unicode, unique = False)
	description = db.Column(db.Unicode, unique = False)
	location = db.Column(db.Unicode, unique = False)
	expected_number_visitors = db.Column(db.Integer, unique = False)
	number_of_hosts = db.Column(db.Integer, unique = False)
	hosts = db.Column(db.JSON, unique = False)
	hosting_organization = db.Column(db.Unicode, unique=False)
	organizer_id = db.Column(db.Unicode, unique=False)

	def __init__(self, name, start_date, end_date, location, expected_number_visitors, number_of_hosts, hosts, start_time, end_time, description, hosting_organization, organizer_id):
		self.name = name
		self.start_date = start_date
		self.end_date = end_date
		self.location = location
		self.expected_number_visitors = expected_number_visitors
		self.number_of_hosts = number_of_hosts
		self.hosts = hosts
		self.start_time = start_time
		self.end_time = end_time
		self.description = description
		self.hosting_organization = hosting_organization
		self.organizer_id = organizer_id

class EventSchema(ma.Schema):
	class Meta:
		fields = ('event_id', 'name', 'start_date', 'end_date', 'location', 'expected_number_visitors', 'number_of_hosts', 'hosts', 'start_time', 'end_time', 'description', 'hosting_organization', 'organizer_id')

event_schema = EventSchema()
events_schema = EventSchema(many = True)

@app.route("/event", methods=["POST"])
def event_add():
	name = request.json['name']
	start_date = request.json['start_date']
	end_date = request.json['end_date']
	location = request.json['location']
	expected_number_visitors = request.json['expected_number_visitors']
	number_of_hosts = request.json['number_of_hosts']
	hosts = request.json['hosts']
	start_time = request.json['start_time']
	end_time = request.json['end_time']
	description = request.json['description']
	hosting_organization = request.json['hosting_organization']
	organizer_id = request.json['organizer_id']

	new_event = Event(name, start_date, end_date, location, expected_number_visitors, number_of_hosts, hosts, start_time, end_time, description, hosting_organization, organizer_id)
	db.session.add(new_event)
	db.session.commit()
	return event_schema.jsonify(new_event)

@app.route("/event/update/<event_id>", methods=["POST"])
def event_update_info(event_id):

	event = Event.query.get(event_id)
	event.name = request.json['name']
	event.start_date = request.json['start_date']
	event.end_date = request.json['end_date']
	event.location = request.json['location']
	event.expected_number_visitors = request.json['expected_number_visitors']
	event.number_of_hosts = request.json['number_of_hosts']
	event.hosts = request.json['hosts']
	event.start_time = request.json['start_time']
	event.end_time = request.json['end_time']
	event.description = request.json['description']
	event.hosting_organization = request.json['hosting_organization']
	event.organizer_id = request.json['organizer_id']

	db.session.commit()
	return event_schema.jsonify(event)

@app.route("/event/<event_id>", methods=["GET"])
def event_get(event_id):
	event = Event.query.get(event_id)
	return event_schema.jsonify(event)

@app.route("/event/addHost/<event_id>", methods=["POST"])
def event_add_host(event_id):
	event = Event.query.get(event_id)
	event.number_of_hosts = event.number_of_hosts + 1
	return event_schema.jsonify(event)

@app.route("/event/sort_date", methods=["GET"])
def event_sort_date():
	events = Event.query
	result = events.order_by(Event.start_date).all()
	return events_schema.jsonify(result)

@app.route("/event/most_recently_added", methods=["GET"])
def event_most_recent():
	events = Event.query
	result = events.order_by(Event.event_id.desc()).first()
	return events_schema.jsonify(result)

@app.route("/event/organizersEvents/<organizer_id>", methods=["GET"])
def event_get_organizers_events():
	result = Event.query.filter_by(organizer_id=organizer_id)
	return events_schema.jsonify(result)


@app.route("/event/delete/<event_id>", methods=["DELETE"])
def event_delete(event_id):
	event = Event.query.get(event_id)
	db.session.delete(event)
	db.session.commit()
	return event_schema.jsonify(event)




#------------------------------------------------------------------------------------------
class Host(db.Model):
	host_id = db.Column(db.Integer, primary_key = True)
	netid = db.Column(db.Unicode, unique = True)
	name = db.Column(db.Unicode, unique = False)
	email = db.Column(db.Unicode, unique = False)
	campus_organizations = db.Column(db.Unicode, unique = False)
	hosting_address = db.Column(db.Unicode, unique = False)
	max_visitors = db.Column(db.Integer, unique = False)
	gender = db.Column(db.Unicode, unique = False)
	same_gender = db.Column(db.Boolean, unique = False)
	expandable = db.Column(db.Boolean, unique = False)
	additional_visitors = db.Column(db.Integer, unique = False)

	def __init__(self, netid, name, email, campus_organizations, hosting_address, max_visitors, gender, same_gender, expandable, additional_visitors):
		self.netid = netid
		self.name = name
		self.email = email
		self.campus_organizations = campus_organizations
		self.hosting_address = hosting_address
		self.max_visitors = max_visitors
		self.gender = gender
		self.same_gender = same_gender
		self.expandable = expandable
		self.additional_visitors = additional_visitors

class HostSchema(ma.Schema):
	class Meta:
		fields = ('host_id', 'netid', 'name', 'email', 'campus_organizations', 'hosting_address', 'max_visitors', 'gender', 'same_gender', 'expandable', 'additional_visitors')

host_schema = HostSchema()
hosts_schema = HostSchema(many = True)

@app.route("/host", methods=["POST"])
def host_add():
	netid = request.json['netid']
	name = request.json['name']
	email = request.json['email']
	campus_organizations = request.json['campus_organizations']
	hosting_address = request.json['hosting_address']
	max_visitors = request.json['max_visitors']
	gender = request.json['gender']
	same_gender = request.json['same_gender']
	expandable = request.json['expandable']
	additional_visitors = request.json['additional_visitors']

	new_host = Host(netid, name, email, campus_organizations, hosting_address, max_visitors, gender, same_gender, expandable, additional_visitors)

	db.session.add(new_host)
	db.session.commit()
	return host_schema.jsonify(new_host)

@app.route("/host/<host_id>", methods=["GET"])
def host_get(host_id):
	host = Host.query.get(host_id)
	return host_schema.jsonify(host)

#-----------------------------------------------------------------------------------------------------------------------------------------
"""class VisitorPairing(db.Model):
	visitorpairing_id = db.Column(db.Integer, primary_key=True)
	visitor_id = db.Column(db.Integer, unique=False)
	event_id = db.Column(db.Integer, unique=False)
	host_id = db.Column(db.Integer, unique=False)

class VisitorPairingSchema(db.Model):
	class Meta:
		fields = ('visitorpairing_id', 'visitor_id', 'event_id', 'host_id')

visitorpairing_schema = VisitorPairingSchema()
visitorpairings_schema = VisitorPairingSchema(many = True)"""
#-----------------------------------------------------------------------------------------------------------------------------------------
class Pairing(db.Model):
	pairing_id = db.Column(db.Integer, primary_key=True)
	host_id = db.Column(db.Integer, unique=False)
	event_id = db.Column(db.Integer, unique=False)
	host_gender = db.Column(db.Unicode, unique=False)
	same_gender_room = db.Column(db.Boolean, unique=False)
	host_room_num = db.Column(db.Unicode, unique=False)
	max_visitors = db.Column(db.Unicode, unique=False)
	num_visitors = db.Column(db.Integer, unique =False)
	host_first_name = db.Column(db.Unicode, unique=False)
	host_last_name = db.Column(db.Unicode, unique=False)
	host_cellphone = db.Column(db.Unicode, unique=False)

	def __init__(self, host_id, event_id, host_gender, same_gender_room, host_room_num, max_visitors, num_visitors, host_first_name, host_last_name, host_cellphone):
		self.host_id = host_id
		self.event_id = event_id
		self.host_gender = host_gender
		self.same_gender_room = same_gender_room
		self.host_room_num = host_room_num
		self.max_visitors = max_visitors
		self.num_visitors = num_visitors
		self.host_first_name = host_first_name
		self.host_last_name = host_last_name
		self.host_cellphone = host_cellphone


class PairingSchema(ma.Schema):
	class Meta:
		fields = ('pairing_id', 'host_id', 'event_id', 'host_gender', 'same_gender_room', 'host_room_num', 'max_visitors', 'num_visitors' 'host_first_name', 'host_last_name', 'host_cellphone')

pairing_schema = PairingSchema()
pairings_schema = PairingSchema(many = True)

@app.route("/pairing", methods=["POST"])
def pairing_add():
	host_id = request.json['host_id']
	event_id = request.json['event_id']
	host_gender = request.json['host_gender']
	same_gender_room = request.json['same_gender_room']
	host_room_num = request.json['host_room_num']
	max_visitors = request.json['max_visitors']
	num_visitors = request.json['num_visitors']
	host_first_name = request.json['host_first_name']
	host_last_name = request.json['host_last_name']
	host_cellphone = request.json['host_cellphone']

	new_pairing = Pairing(host_id, event_id, host_gender, same_gender_room, host_room_num, max_visitors, num_visitors, host_first_name, host_last_name, host_cellphone)

	db.session.add(new_pairing)
	db.session.commit()
	return pairing_schema.jsonify(new_pairing)

@app.route("/pairing/<pairing_id>", methods=["GET"])
def pairing_get(pairing_id):
	pairing = Pairing.query.get(pairing_id)
	return pairing_schema.jsonify(pairing)


@app.route("/pairing/events_for_host/<host_id>", methods=["GET"])
def pairing_get_event_for_host(host_id):
	pairings = Pairing.query.filter_by(host_id=host_id).all()
	return pairings_schema.jsonify(pairings)

@app.route("/pairing/hosts_for_event/<event_id>", methods=["GET"])
@jwt_required
def pairing_get_host_for_event(event_id):
	pairings = Pairing.query.filter_by(event_id=event_id).all()
	return pairings_schema.jsonify(pairings)

@app.route("/pairing/addVisitor/<pairing_id>", methods=["POST"])
@jwt_required
def pairing_add_visitor(pairing_id):
	pairing = Pairing.query.get(pairing_id)
	pairing.num_visitors = pairing.num_visitors + 1
	return pairing_schema.jsonify(event)

@app.route("/pairing/removeVisitor/<pairing_id>", methods=["POST"])
@jwt_required
def pairing_remove_visitor(pairing_id):
	pairing = Pairing.query.get(pairing_id)
	pairing.num_visitors = pairing.num_visitors - 1
	return pairing_schema.jsonify(event)

@app.route("/pairing/delete/<pairing_id>", methods=["DELETE"])
def pairing_delete(pairing_id):
	pairing = Pairing.query.get(pairing_id)
	return pairing_shema.jsonify(pairing)


#-----------------------------------------------------------------------------------------------------------------------------------------
class VisitorPairing(db.Model):
	visitor_pairing_id = db.Column(db.Integer, primary_key = True)
	visitor_id = db.Column(db.Integer, unique=False)
	visitor_email = db.Column(db.Unicode, unique=False)
	host_id = db.Column(db.Integer, unique=False)
	event_id = db.Column(db.Integer, unique=False)
	pairing_id = db.Column(db.Unicode, unique=False)

	def __init__(self, visitor_id, visitor_email, host_id, event_id, pairing_id):
		self.visitor_id = visitor_id
		self.visitor_email = visitor_email
		self.host_id = host_id
		self.event_id = event_id 
		self.pairing_id = pairing_id

class VisitorPairingSchema(ma.Schema):
	class Meta:
		fields=('visitor_pairing_id', 'visitor_id', 'visitor_email', 'host_id', 'event_id', 'event_name', 'pairing_id')

visitor_pairing_schema = VisitorPairingSchema()
visitor_pairings_schema = VisitorPairingSchema(many = True)


@app.route("/visitor_pairing", methods=["POST"])
@jwt_required
def visitor_pairing_add():
	visitor_id = request.json['visitor_id']
	visitor_email = request.json['visitor_email']
	host_id = request.json['host_id']
	event_id = request.json['event_id']
	pairing_id = request.json['pairing_id']
	new_visitor_pairing = VisitorPairing(visitor_id, visitor_email, host_id, event_id, pairing_id)
	db.session.add(new_visitor_pairing)
	db.session.commit()
	return visitor_pairing_schema.jsonify(new_visitor_pairing)

@app.route("/visitor_pairing/delete/<visitor_pairing_id>", methods=["DELETE"])
def visitor_pairing_delete(visitor_pairing_id):
	visitor_pairing = VisitorPairing.query.get(visitor_pairing_id)
	return visitor_pairing_shema.jsonify(visitor_pairing)


@app.route("/visitor_pairing/guests_in_room/<pairing_id>", methods=["GET"])
@jwt_required
def visitor_pairing_get_guests_in_room(pairing_id):
	count = VisitorPairing.query.filter_by(pairing_id=pairing_id).count()
	return str(count)


#-----------------------------------------------------------------------------------------------------------------------------------------
class Eligibilities(db.Model):
	eligibility_id = db.Column(db.Integer, primary_key = True)
	visitor_email = db.Column(db.Unicode, unique=False)
	event_id = db.Column(db.Unicode, unique=False)
	event_name = db.Column(db.Unicode, unique=False)

	def __init__(self, visitor_email, event_id, event_name):
		self.visitor_email = visitor_email
		self.event_id = event_id
		self.event_name = event_name

class EligibilitySchema(ma.Schema):
	class Meta:
		fields=('eligibility_id', 'visitor_email', 'event_id', 'event_name')


eligibility_schema = EligibilitySchema()
eligibilities_schema = EligibilitySchema(many = True)

@app.route("/eligibility", methods=["POST"])
def eligibility_add():
	visitor_email = request.json['visitor_email']
	event_id = request.json['event_id']
	event_name = request.json['event_name']
	new_eligibility = Eligibilities(visitor_email, event_id, event_name)
	db.session.add(new_eligibility)
	db.session.commit()
	return eligibility_schema.jsonify(new_eligibility)


@app.route("/eligibility/events_for_visitor/<visitor_email>", methods=["GET"])
def eligibility_events_for_visitor(visitor_email):
	eligibilities = Eligibilities.query.filter_by(visitor_email=visitor_email).all()
	return eligibilities_schema.jsonify(eligibilities)


#-----------------------------------------------------------------------------------------------------------------------------------------
class Visitor(db.Model):
	id = db.Column(db.Integer, primary_key = True)
	gender = db.Column(db.Unicode, unique = False)
	name = db.Column(db.Unicode, unique = False)
	same_gender = db.Column(db.Boolean, unique = False)
	university = db.Column(db.Unicode, unique = False)
	email = db.Column(db.Unicode, unique = True)
	password = db.Column(db.Unicode, unique = False)

	def __init__(self, gender, name, same_gender, university, email, password): 
		self.gender = gender
		self.name = name 
		self.same_gender = same_gender
		self.university = university 
		self.email = email
		self.password = bcrypt.generate_password_hash(password, 10).decode('utf8')

class VisitorSchema(ma.Schema):
	class Meta:
		fields = ('id', 'gender', 'name', 'same_gender', 'university', 'email', 'password')

visitor_schema = VisitorSchema()
visitors_schema = VisitorSchema(many = True)

# def authenticate(username, password):
# 	visitor = Visitor.query.filter_by(email=username).first()
# 	if visitor and bcrypt.check_password_hash(visitor.password, password):
# 		return visitor

# def identity(payload):
# 	id = payload['identity']
# 	return Visitor.query.filter_by(id=id).first()

@app.route("/visitor", methods=["POST"])
def visitor_add():
	gender = request.json['gender']
	name = request.json['name']
	same_gender = request.json['same_gender']
	university = request.json['university']
	email = request.json['email']
	password = request.json['password']

	new_visitor = Visitor(gender, name, same_gender, university, email, password)
	db.session.add(new_visitor)
	db.session.commit()	
	identity = {
		"id": new_visitor.id,
		"email": new_visitor.email
	}
	access_token = create_access_token(identity=identity)
	return jsonify(access_token=access_token), 200
	
@app.route("/visitor/login", methods=["POST"])
def visitor_login():
	email = request.json['email']
	password = request.json['password']
	visitor = Visitor.query.filter_by(email=email).first()

	if visitor and bcrypt.check_password_hash(visitor.password, password):
		identity = {
			"id": visitor.id,
			"email": visitor.email
		}
		access_token = create_access_token(identity=identity)
		return jsonify(access_token=access_token), 200

	return jsonify({"msg": "Bad username or password"}), 401

@app.route("/visitor/reset", methods=["POST"])
def visitor_reset():
	email = request.json['email']
	visitor = Visitor.query.filter_by(email=email).first()

	if visitor:
		# Expire token in 60 minutes
		reset_token = jwt.encode({"id": visitor.id, "exp": int(time.time()) + 60*60}, app.config['JWT_SECRET_KEY'], algorithm='HS256')

		message = Mail(
			from_email='from_email@example.com',
			to_emails=email,
			subject='Password Reset',
			html_content='http://localhost:3000/visitor/reset?resetToken='+reset_token.decode("utf-8") )
		try:
			sg = SendGridAPIClient(os.environ.get('SENDGRID_API_KEY'))
			response = sg.send(message)
			print(response.status_code)
			print(response.body)
			print(response.headers)
			return jsonify(), 200
		except Exception as e:
			print(e.message)
			return jsonify(), 500
	
	return jsonify({"msg": "Invalid user"}), 401


@app.route("/visitor/change-password", methods=["POST"])
def visitor_change_password():
	password = request.json['password']
	reset_token = jwt.decode(request.json['resetToken'], app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
	visitor = Visitor.query.get(reset_token["id"])
	print(visitor)

	if visitor:
		visitor.password = bcrypt.generate_password_hash(password, 10).decode('utf8')
		db.session.commit()
		return jsonify({"msg": "Updated"}), 200
	
	return jsonify({"msg": "Invalid user"}), 401


@app.route("/visitor/<visitor_id>", methods=["GET"])
def visitor_get(visitor_id):
	visitor = Visitor.query.get(visitor_id)
	return visitor_schema.jsonify(host)

@app.route('/visitor/data')
@jwt_required
def protected():
	visitor_id = get_jwt_identity()['id']
	visitor = Visitor.query.get(visitor_id)
	return visitor_schema.jsonify(visitor)


db.create_all()
#---------------------------------------------------------------------------------------------------
if __name__ == '__main__':
	app.run(debug=True, host='0.0.0.0', port=os.environ.get("PORT", 5000))