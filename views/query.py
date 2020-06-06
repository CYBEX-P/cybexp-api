if __name__ in ["__main__", "query"]:
  from crypto import encrypt_file
else:
  from .crypto import encrypt_file

import os, time, socket, uuid, secrets, logging

import falcon
from pymongo import MongoClient

from tahoe import TDQL, get_query_backend, get_report_backend
from tahoe.misc import canonical

# === Debug ===
import pdb
from pprint import pprint


# === Query Class ===

class Query(object):
  query_backend = get_query_backend()
  report_backend = get_report_backend()
  
  def on_post(self, req, resp):
    try:
      try:
        query_type = req.media.pop('type')
        query_data = req.media.pop('data')
      except (KeyError, falcon.errors.HTTPBadRequest) as err:
        resp.media, resp.status = {"message" : "Invalid query format! " + repr(err) + str(err)}, falcon.HTTP_400
        return     
      
      userid = "identity--2b419244-b973-4d6e-94c5-378db82d8efa" # placeholder, replace with PyJWT
      
      canonical_data = canonical(query_data)
      encrypted_data = str(encrypt_file(canonical_data.encode()))
      
      query = TDQL(query_type, query_data, userid, time.time())
      query.update({'data' : {'encrypted_data':encrypted_data}})
      
      if query.status == 'ready':
        resp.media = self.report_backend.find_one({'uuid':query.report_id})
        resp.status = falcon.HTTP_201
        return
          
      elif query.status == 'processing':
        resp.status = falcon.HTTP_202
        resp.media = {"message" : "Please check back later on report_url", "report_url" : "/query/" + query.uuid}
        return
        
      # query.status == 'wait'
        
      if os.name in ['nt', 'posix']:      # create elif block for 'posix'
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
        resp.media = {"message" : "Please check back later on report_url", "report_url" : "/query/" + query.uuid}
    
    except:
      logging.exception("api.views.query.Query")
      resp.media, resp.status = {"message":"Server Error!"}, falcon.HTTP_500
    
    
