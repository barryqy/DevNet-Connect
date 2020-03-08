import requests
import json

bearer = "<YOUR BEARER HERE>"
roomid = "<YOUR ROOM ID HERE>"
def sendWebExPOST(msg):
    """
    This method is used for:
        -posting a message to the WebEx-Teams(Spark) room to confirm that a command was received and processed
    """
    headers = {"Accept": "application/json",
               "Content-Type": "application/json",
               "Authorization": "Bearer " + bearer}
    data = {"roomId": roomid, "text": msg} 

    contents = requests.post("https://api.ciscospark.com/v1/messages", json.dumps(data),
                             headers=headers)
    return contents