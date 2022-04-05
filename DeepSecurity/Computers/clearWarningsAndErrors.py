from ast import If, Try
import json, sys
import urllib3
from requests import Session
from urllib.parse import urlparse
from zeep import Client
from zeep.transports import Transport

# Disable certificate verification and console warnings
session = Session()
session.verify = False
transport = Transport(session=session)
urllib3.disable_warnings()

manager = input ("Ender DSM Hostname and Port, ex: dsm.lab.local:4119: ")
apiKey = input ("Enter Cloud One ApiKey: ")
alertToClear = input ("Enter Alert to clear: ")
username = input ("Enter Username: ")
password = input ("Enter Password: ")

headers = {
    'api-version': 'v1',
    'api-secret-key': apiKey,
    'Content-Type': 'application/json'
}

# Inspec wsdl: python3 -mzeep https://'+manager+'/webservice/Manager?WSDL
soapClient = Client('https://'+manager+'/webservice/Manager?WSDL', transport=transport)

try:
    sID = soapClient.service.authenticate(username, password)
except:
    print("An exception occurred")

loopStatus = 0
hostID = 0
computerSearchUrl = 'https://'+manager+'/api/computers/search?expand=computerStatus'

# Loop through all activated computers
while (loopStatus < 1):
    
    # Computer Search payload
    payload = json.dumps({
        "maxItems": 5000,
        "searchCriteria": [
        {
            "idValue": hostID,
            "idTest": "greater-than"
        },
        {
            "fieldName": "lastIPUsed",
            "stringTest": "not-equal",
            "stringValue": ""
        }
    ],
    "sortByObjectID": True
    })

    http = urllib3.PoolManager(cert_reqs='CERT_NONE')
    encoded_payload = payload.encode("utf-8")
    try:
        computerSearchResponse = http.request("POST", url=computerSearchUrl, headers=headers, body=encoded_payload)
    except:
        loopStatus = 1
    computerSearchResponseJson = json.loads(computerSearchResponse.data)

    # Check results of computer search
    if not len(computerSearchResponseJson['computers']) == 0:
        for item in computerSearchResponseJson['computers']:
            hostName = item['hostName']
            hostID = item['ID']
            agentStatusMessages = item["computerStatus"]["agentStatusMessages"]
            if alertToClear in agentStatusMessages:
                print(hostName)
                print(agentStatusMessages)
                print('Clearing warnings and errors on '+hostName)
                soapClient.service.hostClearWarningsErrors(hostID, sID)
    else:
        loopStatus = 1
        soapClient.service.endSession(sID)