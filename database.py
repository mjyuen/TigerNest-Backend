from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
from flask_cors import CORS
import os
import hashlib
import json

basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
CORS(app)
app.config['SQLALCHEMY_DATABASE_URI'] = "postgresql://postgres:p@localhost:5432/tigernest"
#app.config['SQLALCHEMY_DATABASE_URI'] = "postgresql://localhost/tigernest"


db = SQLAlchemy(app)
ma = Marshmallow(app)

#------------------------------------------------------------------------------------------

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

@app.route("/event/<event_id>", methods=["GET"])
def event_get(event_id):
	event = Event.query.get(event_id)
	return event_schema.jsonify(event)

@app.route("/event/<event_id>", methods=["POST"])
def event_add_host(event_id):
	event = Event.query.get(event_id)
	event.number_of_hosts = event.number_of_hosts + 1
	return event_schema.jsonify(event)

@app.route("/event/sort_date", methods=["GET"])
def event_get_all():
	events = Event.query
	result = events.order_by(Event.start_date).all()
	return events_schema.jsonify(result)


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

#------------------------------------------------------------------------------------------
class Visitor(db.Model):
	visitor_id = db.Column(db.Integer, primary_key = True)
	gender = db.Column(db.Unicode, unique = False)
	name = db.Column(db.Unicode, unique = False)
	same_gender = db.Column(db.Boolean, unique = False)
	university = db.Column(db.Unicode, unique = False)
	email = db.Column(db.Unicode, unique = False)

	def __init__(self, gender, name, same_gender, university, email): 
		self.gender = gender
		self.name = name 
		self.same_gender = same_gender
		self.university = university 
		self.email = email

class VisitorSchema(ma.Schema):
	class Meta:
		fields = ('visitor_id', 'gender', 'name', 'same_gender', 'university', 'email')

visitor_schema = VisitorSchema()
visitors_schema = VisitorSchema(many = True)

@app.route("/visitor", methods=["POST"])
def visitor_add():
	gender = request.json['gender']
	name = request.json['name']
	same_gender = request.json['same_gender']
	university = request.json['university']
	email = request.json['email']

	new_visitor = Visitor(gender, name, same_gender, university, email)
	db.session.add(new_visitor)
	db.session.commit()
	return event_schema.jsonify(new_visitor)

@app.route("/visitor/<visitor_id>", methods=["GET"])
def visitor_get(visitor_id):
	visitor = Visitor.query.get(visitor_id)
	return visitor_schema.jsonify(host)

db.create_all()
#---------------------------------------------------------------------------------------------------
if __name__ == '__main__':
	app.run(debug=True, host='0.0.0.0', port=os.environ.get("PORT", 5000))