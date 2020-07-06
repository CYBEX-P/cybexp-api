import falcon
import logging
import os
import pdb
import secrets
import socket
import time
import uuid

from tahoe import Instance, TDQL
from tahoe.misc import canonical

import loadconfig
from .crypto import encrypt_file


_BACKEND = loadconfig.get_report_backend()
Instance._backend = _BACKEND


# === Query Class ===

class Query:
    report_backend = _BACKEND
  
    def on_post(self, req, resp):
        try:
            try:
                query_type = req.media.pop('type')
                query_data = req.media.pop('data')
            except (KeyError, falcon.errors.HTTPBadRequest) as err:
                resp.media = {"message" : "Invalid query format! " + \
                              repr(err) + str(err)}
                resp.status = falcon.HTTP_400
                return     
      
            userid = "identity--2b419244-b973-4d6e-94c5-378db82d8efa" # placeholder, replace with PyJWT
      
            canonical_data = canonical(query_data).encode()
            encrypted_data = str(encrypt_file(canonical_data))
      
            query = TDQL(query_type, query_data, userid, time.time())
            query._update({'data' : {'encrypted_data': encrypted_data}})
          
            if query.status == 'ready':
                report = self.report_backend.find_one(
                    {'_hash': query.report_id}, {'_id': 0})
                resp.media = report['data']
                resp.status = falcon.HTTP_201
                return
              
            elif query.status == 'processing':
                resp.status = falcon.HTTP_202
                resp.media = {"message":"check back later", "status":"processing"}
                #{"message" : "Please check back later on report_url", "report_url" : "/query/" + query.uuid}
                return

            # query.status == 'wait'
            
            if os.name in ['nt', 'posix']:      # create elif block for 'posix'
                sock = socket.socket()
                sock.bind(('', 0))  
                host, port = sock.getsockname()
                nonce = secrets.token_hex(16)     # password # encrypt nonce
                sock.settimeout(5)                # 5 seconds
                sock.listen()
              
                query.setsocket(host, port, nonce)
                query.setstatus('wait')
                
                status = 202
                while True:
                    try:
                        r = sock.accept()[0] # vulnerability: if an attacker keeps sending wrong nonce continuously, we will be stuck here forever
                        r = r.recv(64)
                        if r == nonce.encode():
                            status = 201
                            break
                    except socket.timeout:
                        break
                sock.close()

            if status == 201:
                query = self.report_backend.find_one(
                    {'_hash': query._hash})
                report = self.report_backend.find_one(
                    {'_hash': query['report_id']}, {'_id': 0})
                resp.media = report['data']
                resp.status = falcon.HTTP_201
            elif status == 202:
                resp.status = falcon.HTTP_202
                resp.media = {"message":"check back later", "status":"processing"}
    
        except:
            logging.exception("api.views.query.Query")
            resp.media = {"message":"Server Error!"}
            resp.status = falcon.HTTP_500
    


