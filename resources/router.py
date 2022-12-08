from flask import Response, request
from flask_restful import Resource
from flask_jwt_extended import jwt_required
from ncclient import manager
import xmltodict, json, requests

# Expires every 12 hours. Automatic access tokens require Webex Integration, which involves using OAuth
access_token = 'YWFjYzBhYWMtZmVhOC00YzU4LWI4YWItN2Y5ZmE0NjMxZjIyOWM1YjE1M2MtMzc5_P0A1_4fbc8836-28d2-47cd-9b80-e05ba83c5673'
# Room ID of TIP Flower Boys
room_id = 'Y2lzY29zcGFyazovL3VybjpURUFNOnVzLXdlc3QtMl9yL1JPT00vZmZkNzc0ZjAtMWRjMC0xMWVkLWFhYmYtYmJkZGJkOTIwYzNk'

m = manager.connect(
    host="sandbox-iosxe-recomm-1.cisco.com",
    port=830,
    username="developer",
    password="C1sco12345",
    hostkey_verify=False
)

class RouterApi(Resource):
    #show running configuration
    @jwt_required()
    def get(self):
        netconf_filter = """
        <filter>
            <native xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-native" />
        </filter>
        """
        netconf_reply = m.get_config(source="running", filter=netconf_filter)
        return Response(json.dumps(xmltodict.parse(netconf_reply.xml)), mimetype="application/json", status=200)
    #change hostname
    @jwt_required()
    def post(self):
        body = request.get_json()
        hostname = body['hostname']
        netconf_hostname = """
        <config>
          <native xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-native">
             <hostname>{}</hostname>
          </native>
        </config>
        """.format(hostname)
        netconf_reply = m.edit_config(target="running", config=netconf_hostname)
        message = 'Attention: A member of L1 SE Team changed the hostname of the router to {}'.format(hostname)
        url = 'https://webexapis.com/v1/messages'
        headers = {
            'Authorization': 'Bearer {}'.format(access_token),
            'Content-Type': 'application/json'
        }
        params = {'roomId': room_id, 'markdown': message}
        res = requests.post(url, headers=headers, json=params)
        print(res.json())
        return Response(json.dumps(xmltodict.parse(netconf_reply.xml)), mimetype="application/json", status=200)