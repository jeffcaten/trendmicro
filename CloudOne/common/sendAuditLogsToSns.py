import json
import time
import boto3
import urllib3
from urllib.parse import urlparse

# Configuration

###################################################
region = "us-1" # Options: us-1
key = "" # Cloud One API key
snsArn = ""
###################################################

def listUsers(key):
    users = []
    url = "https://accounts.cloudone.trendmicro.com/api/users?limit=25"
    extra = ""
    headers = {"Api-Version": "v1", "Authorization": "ApiKey " + key,}

    while True:
        http = urllib3.PoolManager()
        r = http.request("GET", url=url + extra, headers=headers)

        if r.status == 429:
            time.sleep(0.5)
            r = http.request("GET", url=url + extra, headers=headers)
            if r.status == 429:
                time.sleep(1)
                r = http.request("GET", url=url + extra, headers=headers)
                if r.status == 429:
                    time.sleep(2)
                    r = http.request("GET", url=url + extra, headers=headers)
        
        if r.status == 200:
            responseObject = json.loads(r.data.decode("utf-8"))
            #responseObject = r.data()
            users += responseObject["users"]
        else:
            print("Failed to get users")
            print(r.text)
            break

        try:
            next = responseObject["next"]
            extra = "&cursor=" + next
        except KeyError:
            break
    return users

def listEvents(key):
    logs = []
    url = "https://audit." + region + ".cloudone.trendmicro.com/api/logs?limit=2"
    extra = ""
    headers = {"Api-Version": "v1", "Authorization": "ApiKey " + key,}

    while True:
        http = urllib3.PoolManager()
        r = http.request("GET", url=url + extra, headers=headers)


        if r.status == 429:
            time.sleep(0.5)
            r = http.request("GET", url=url + extra, headers=headers)
            if r.status == 429:
                time.sleep(1)
                r = http.request("GET", url=url + extra, headers=headers)
                if r.status == 429:
                    time.sleep(2)
                    r = http.request("GET", url=url + extra, headers=headers)

        if r.status == 200:
            responseObject = json.loads(r.data.decode("utf-8"))
            #responseObject = r.json()
            logs += responseObject["logs"]
        else:
            print("Failed to get the audit logs")
            print(r.text)
            break

        try:
            next = responseObject["next"]
            extra = "&cursor=" + next
        except KeyError:
            break
    return logs

def addUserNametoLogs(users, logs):
    # Loop through all of the logs
    for log in logs:
        l_principalURN = log["principalURN"]

        # Loop through all of the users
        for user in users:
            # Check list of users to see if there is a matching urn
            if l_principalURN == user["urn"]:
                #u_urn = user["urn"]
                u_email = user["email"]
        # Append user email (u_email) to current log
        log['email'] = u_email
    return logs

def sendLogsToSns(logs):
    message = logs
    client = boto3.client('sns')
    response = client.publish(
        TargetArn=snsArn,
        Message=json.dumps({'default': json.dumps(message)}),
        MessageStructure='json'
    )
    print(message)

def lambda_handler(event, context):
    # Get a list of C1 Users
    users = listUsers(key)
    # Get a list of C1 audit events
    logs = listEvents(key)
    # Add user email to audit events
    logs = addUserNametoLogs(users, logs)
    sendLogsToSns(logs)
    
    return {
        'statusCode': 200,
        'body': json.dumps('Hello from Lambda!')
    }