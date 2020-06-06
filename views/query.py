import os, time, socket, uuid, secrets

import falcon
from pymongo import MongoClient

from tahoe import TDQL, get_query_backend, get_report_backend

# === Debug ===
import pdb
from pprint import pprint


# === Query Class ===

class Query(object):
  query_backend = get_query_backend()
  report_backend = get_report_backend()
  
  def on_post(self, req, resp):
    try:
      query_type = req.media.pop('type')
      query_data = req.media.pop('data')
    except:
      pdb.set_trace()
      resp.media = {"msg" : "Invalid query format!"}
      resp.status = falcon.HTTP_400
      return
    
    userid = "identity--2b419244-b973-4d6e-94c5-378db82d8efa" # placeholder
    
    query = TDQL(query_type, query_data, userid, time.time())
    
    if query.status == 'ready':
      resp.media = self.report_backend.find_one({'uuid':query.report_id})
      resp.status = falcon.HTTP_201
      return
        
    elif query.status == 'processing':
      resp.status = falcon.HTTP_202
      resp.media = {"msg" : "Please check back later on report_url", "report_url" : "/query/" + query.uuid}
      return
      
    # query.status == 'wait'
      
    if os.name == 'nt':
      sock = socket.socket()
      sock.bind(('', 0))
      host, port = sock.getsockname()
      nonce = secrets.token_hex(16)     # password
      sock.settimeout(5)                # 5 seconds
      sock.listen()

      query.setsocket(host, port, nonce)    
      
      status = 202
      while True:
        try:
          r = sock.accept()[0]
          r = r.recv(64)
          if r == nonce.encode():
            status = 201
            break
        except socket.timeout:
          break
      sock.close()

      if status == 201:
        resp.status = falcon.HTTP_201
        resp.media = self.report_backend.find_one({'nonce': nonce})
      elif status == 202:
        resp.status = falcon.HTTP_202
        resp.media = {"msg" : "Please check back later on report_url", "report_url" : "/query/" + query.uuid}
      
    
    
