import os
import json
from time import sleep
from datetime import timezone
import pprint
import base64
import time
import sys

from algosdk.v2client import indexer

indexer_token = "a" * 64
myindexer = indexer.IndexerClient(indexer_token=indexer_token, indexer_address='http://localhost:8980')

note_prefix = 'publishMessage'.encode()

next_round = 24

while True:
    nexttoken = ""
    while True:
        response = myindexer.search_transactions( min_round=next_round, note_prefix=note_prefix, next_page=nexttoken)
        pprint.pprint(response)
        if 'next-token' in response:
            nexttoken = response['next-token']
        else:
            next_round = response['current-round'] + 1
            break
    time.sleep(1)
