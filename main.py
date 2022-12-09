from flask import Flask, Response, request, jsonify
from flask_jwt_extended import jwt_required, JWTManager, create_access_token, get_jwt_identity
from pymongo import MongoClient
from ncclient import manager
from ncclient.operations import RPCError
from bson import json_util
from bson.objectid import ObjectId
import hashlib, jwt, xmltodict, json, requests
from datetime import datetime 

# Define a secret key for signing the JWT
secret_key = 'secret-key'

# Create a Flask app
app = Flask(__name__)

# Create a JWTManager object
jwt = JWTManager(app)

# Initialize the JWTManager object with the Flask application
jwt.init_app(app)

app.config['JWT_SECRET_KEY'] = 'Devasc Finals Case Study'

# Connect to MongoDB Atlas
client = MongoClient("mongodb+srv://group-3-software-design:YCpTgKjSJYY17sBF@consultsched.81dxtxh.mongodb.net/?retryWrites=true&w=majority")
db = client.test2

device = {
        'host': 'sandbox-iosxe-recomm-1.cisco.com',
        'port': 830,
        'username': 'developer',
        'password': 'C1sco12345',
    }

# Webex token that expires every 12 hours
access_token = 'NzVkYzQ5Y2QtZjAxMi00ZThiLWJhZDItNDU1OGRiZTEyNGVkY2QzZTUxYzctOTY1_P0A1_4fbc8836-28d2-47cd-9b80-e05ba83c5673'
# Room ID for TIP Flower Boys
room_id = 'Y2lzY29zcGFyazovL3VybjpURUFNOnVzLXdlc3QtMl9yL1JPT00vZmZkNzc0ZjAtMWRjMC0xMWVkLWFhYmYtYmJkZGJkOTIwYzNk'

def get_running_config_using_netconf():
    # Connect to the NETCONF device
    filter = """
        <filter>
            <native xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-native" />
        </filter>
        """
    with manager.connect(**device) as m:
        # Send a <get-config> NETCONF operation
        try:
            result = m.get_config(source='running', filter=filter)
            return Response(json.dumps(xmltodict.parse(result.xml)), mimetype="application/json")
        except RPCError as e:
            print(f'NETCONF operation failed: {e}')
            return None

def change_hostname_using_netconf(hostname):
    # Connect to the NETCONF device
    with manager.connect(**device) as m:
        # Build the XML configuration to change the hostname
        config = f"""
        <config>
          <native xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-native">
             <hostname>{hostname}</hostname>
          </native>
        </config>
        """

        # Send an <edit-config> NETCONF operation
        try:
            result = m.edit_config(target='running', config=config)
            message = 'A member of L2 NE Team has approved or changed the hostname of the router to {}'.format(hostname)
            url = 'https://webexapis.com/v1/messages'
            headers = {
                'Authorization': 'Bearer {}'.format(access_token),
                'Content-Type': 'application/json'
            }
            params = {'roomId': room_id, 'markdown': message}
            res = requests.post(url, headers=headers, json=params)
            print(res.json())
            return Response(json.dumps(xmltodict.parse(result.xml)), mimetype="application/json")
        except RPCError as e:
            print(f'NETCONF operation failed: {e}')
            return None

def add_loopback_using_netconf(name, description, address, mask):
    # Connect to the NETCONF device
    with manager.connect(**device) as m:
         # Define the loopback configuration in XML format
        config = f"""
        <config>
        <native xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-native">
        <interface>
        <Loopback>
            <name>{name}</name>
            <description>{description}</description>
            <ip>
            <address>
            <primary>
            <address>{address}</address>
            <mask>{mask}</mask>
            </primary>
            </address>
            </ip>
        </Loopback>
        </interface>
        </native>
        </config>
        """

        # Send an <edit-config> NETCONF operation
        try:
            result = m.edit_config(target='running', config=config)
            message = 'A member of L2 NE Team has approved or added / change Loopback{} with an address and mask of {} {}, and a description of "{}"'.format(name, address, mask, description)
            url = 'https://webexapis.com/v1/messages'
            headers = {
                'Authorization': 'Bearer {}'.format(access_token),
                'Content-Type': 'application/json'
            }
            params = {'roomId': room_id, 'markdown': message}
            res = requests.post(url, headers=headers, json=params)
            print(res.json())
            return Response(json.dumps(xmltodict.parse(result.xml)), mimetype="application/json")
        except RPCError as e:
            print(f'NETCONF operation failed: {e}')
            return None

def authenticate_user(email, password):
    # Check if the email exists in the database
    user = db.users.find_one({'email': email})
    if not user:
        return jsonify({'message': 'Invalid email or password'}), 401

    # Use SHA-256 to encrypt the password
    password_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()

    # Check if the password is correct
    if password_hash != user['password']:
        return jsonify({'message': 'Invalid email or password'}), 401
    
    return user is not None

# Define the route for the registration page
@app.route('/register', methods=['POST'])
def register():
    # Get the email and password from the request body
    first_name = request.json['first_name']
    last_name = request.json['last_name']
    email = request.json['email']
    password = request.json['password']

    # Check if the email already exists in the database
    if db.users.find_one({'email': email}):
        return jsonify({'message': 'A user with this email already exists'}), 400

    # Use SHA-256 to encrypt the password
    password_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()

    # Create a new user document
    user = {
        'first_name': first_name,
        'last_name': last_name,
        'email': email, 
        'password': password_hash,
        'isL2': False}
    db.users.insert_one(user)

    return jsonify({'message': 'Successfully registered'}), 201

@app.route('/login', methods=['POST'])
def login():
    # Get the email and password from the request body
    email = request.json['email']
    password = request.json['password']

    if authenticate_user(email, password):
        # Generate a JWT
         token = create_access_token(identity=email)
    else:
        return jsonify({'message': 'Invalid username or password'}), 401

    # Return the JWT to the user
    return jsonify({'token': token})

@app.route('/show_running_config', methods=['GET'])
@jwt_required()
def show_running_config():
    # Use NETCONF to get the running configuration from the router
    running_config = get_running_config_using_netconf()

    # Return the running configuration to the user
    return running_config, 200

@app.route('/changes', methods=['GET'])
@jwt_required()
def get_changes():
    user = db.users.find_one({'email': get_jwt_identity()})
    if (user['isL2'] == False):
        return jsonify({'message': 'This can only be viewed by L2 Network Engineers.'}), 401
    
    changes = db.changes.find()
    changesJson = json_util.dumps(changes)


    return changesJson,200

@app.route('/changes', methods=['POST'])
@jwt_required()
def approve_changes():
    user = db.users.find_one({'email': get_jwt_identity()})
    if (user['isL2'] == False):
        return jsonify({'message': 'This can only be viewed by L2 Network Engineers.'}), 401
    change = db.changes.find_one({"_id": ObjectId(request.args['changes'])})
    if (change['changes'] == "change_hostname"):
        success = change_hostname_using_netconf(change['hostname'])
        if (success):
            change = db.changes.find_one_and_delete({"_id": ObjectId(request.args['changes'])})
            return success, 200
        else:
            return jsonify({'message': 'Failed to change hostname'}), 500
    elif (change['changes'] == "add_loopback"):
        success = add_loopback_using_netconf(change['name'], change['description'], change['address'], change['mask'])
        if (success):
            change = db.changes.find_one_and_delete({"_id": ObjectId(request.args['changes'])})
            return success, 200
        else:
            return jsonify({'message': 'Failed to add loopback address'}), 500
    
@app.route('/changes', methods=['DELETE'])
@jwt_required()
def deny_changes():
    user = db.users.find_one({'email': get_jwt_identity()})
    if (user['isL2'] == False):
        return jsonify({'message': 'This can only be viewed by L2 Network Engineers.'}), 401
    db.changes.find_one_and_delete({"_id": ObjectId(request.args['changes'])})
    changes = db.changes.find()
    changesJson = json_util.dumps(changes)

    return changesJson,200
    
@app.route('/change_hostname', methods=['POST'])
@jwt_required()
def change_hostname():
    # Get the logged in user's claims
    user = db.users.find_one({'email': get_jwt_identity()})

    # Get the new hostname from the request body
    hostname = request.json['hostname']

    if (user['isL2'] == False):
        change = {
            "changes": "change_hostname",
            "hostname": hostname,
            "date": datetime.now()
        }
        db.changes.insert_one(change)
        message = 'A member of L1 SE Team is requesting to change the hostname to "{}"'.format(hostname)
        url = 'https://webexapis.com/v1/messages'
        headers = {
            'Authorization': 'Bearer {}'.format(access_token),
            'Content-Type': 'application/json'
        }
        params = {'roomId': room_id, 'markdown': message}
        res = requests.post(url, headers=headers, json=params)
        print(res.json())
        return jsonify({'message': 'Your change request have been sent to the L2 Network Engineers.'}), 200
    # Use NETCONF to change the hostname of the router
    success = change_hostname_using_netconf(hostname)

    # Return a success message to the user
    if success:
        return success, 200
    else:
        return jsonify({'message': 'Failed to change hostname'}), 500

@app.route('/add_loopback', methods=['POST'])
@jwt_required()
def add_loopback():
    # Get the logged in user's claims
    user = db.users.find_one({'email': get_jwt_identity()})

    # Get the loopback address and mask from the request body
    name = request.json['name']
    description = request.json['description']
    address = request.json['address']
    mask = request.json['mask']

    # Check if name is a number
    if type(int(name)) != int:
        return jsonify({'message': 'Enter a numbered name'}), 401

    if (user['isL2'] == False):
        change = {
            "changes": "add_loopback",
            "name": name,
            "description": description,
            "address": address,
            "mask": mask,
            "date": datetime.now()
        }
        db.changes.insert_one(change)
        message = 'A member of L1 SE Team is requesting to add or change Loopback{} with the address and mask of {} {}, and a description of "{}"'.format(name, address, mask, description)
        url = 'https://webexapis.com/v1/messages'
        headers = {
            'Authorization': 'Bearer {}'.format(access_token),
            'Content-Type': 'application/json'
        }
        params = {'roomId': room_id, 'markdown': message}
        res = requests.post(url, headers=headers, json=params)
        print(res.json())
        return jsonify({'message': 'Your change request have been sent to the L2 Network Engineers.'}), 200

    # Use NETCONF to add the loopback address to the router
    success = add_loopback_using_netconf(name, description, address, mask)

    # Return a success message to the user
    if success:
        return success, 200
    else:
        return jsonify({'message': 'Failed to add loopback address'}), 500

if __name__ == '__main__':
    app.run()