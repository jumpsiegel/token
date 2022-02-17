import os
import json
from time import sleep
from datetime import timezone
import pprint
import base64
import time


#from dateutil.rrule import HOURLY, rrule
#from dateutil.parser import parse

from algosdk.v2client import indexer

indexer_token = "a" * 64
myindexer = indexer.IndexerClient(indexer_token=indexer_token, indexer_address='http://localhost:8980')

def get_txn_response(start_time, end_time):
    """
    Returns all transactions added to the blockchain between 'start_time' and 'end_time'

    """
    # The indexer expacting time inputs to be in RFC 3339 format
    start_time = start_time.astimezone(timezone.utc).isoformat('T')
    end_time = end_time.astimezone(timezone.utc).isoformat('T')

    nexttoken = ""
    numtx = 1

    responses = []

    # Retrieve up-to 1000 transactions at each request.
    while numtx > 0:
        response = myindexer.search_transactions(start_time=start_time, end_time=end_time,
                                                 next_page=nexttoken, limit=1000)
        transactions = response['transactions']
        responses += transactions
        numtx = len(transactions)
        if numtx > 0:
            # pointer to the next chunk of requests
            nexttoken = response['next-token']
    return responses


note_prefix = 'publishMessage'.encode()

while True:
    response = myindexer.search_transactions(limit=10, note_prefix=note_prefix)
    pprint.pprint(response)
    time.sleep(1)
