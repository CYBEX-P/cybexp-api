import falcon
import hashlib
import logging
import os
import pdb
import secrets
import socket
import time
import uuid

if __name__ != 'api.views.query':
    import sys
    J = os.path.join
    sys.path = ['..', J('..', '..')] + sys.path
    del sys

import loadconfig
from .crypto import encrypt_file
from resource.common import validate_token, tahoe

from tahoe import TDQL
from tahoe.misc import canonical

_BACKEND = loadconfig.get_report_backend()
TDQL._backend = _BACKEND


# === Query Class ===

class Query(object):
    report_backend = _BACKEND

    @validate_token
    def on_post(self, req, resp):
        try:
            try:
                qtype = req.media.pop('type')
                qdata = req.media.pop('data')
                qredo = req.media.pop('redo', None)
            except (KeyError, falcon.errors.HTTPBadRequest) as err:
                resp.media = {"message" : "Invalid query format! " + \
                              repr(err) + str(err)}
                resp.status = falcon.HTTP_400
                return     

            user = req.context['user']
            userid = user._hash
      
            canon_qdata = canonical(qdata).encode()
            qhash = hashlib.sha256(canon_qdata).hexdigest()
        
            enc_qdata = str(encrypt_file(canon_qdata))
            
            query = TDQL(qtype, enc_qdata, qhash, userid, time.time())
          
            if not qredo and query.status in ['ready', 'failed']:
                report = self.report_backend.find_one(
                    {'_hash': query.report_id}, {'_id': 0})
                resp.media = report
                resp.status = falcon.HTTP_201
                return
              
            elif not qredo and query.status == 'processing':
                resp.status = falcon.HTTP_202
                resp.media = {"message":"check back later",
                              "status":"processing"}
                return
            
            if os.name in ['nt', 'posix']:
                sock = socket.socket()
                sock.bind(('', 0))  
                host, port = sock.getsockname()
                nonce = secrets.token_hex(16)   # password # encrypt nonce
                sock.settimeout(5)              # 5 seconds
                sock.listen()
              
                query.setsocket(host, port, nonce)
                query.status = 'wait'
                
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
                    {'_hash': query['data']['report_id'][0]}, {'_id': 0})
                resp.media = report
                resp.status = falcon.HTTP_201
            elif status == 202:
                resp.status = falcon.HTTP_202
                resp.media = {"message":"check back later",
                              "status":"processing"}
    
        except:
            logging.error("api.views.query.Query", exc_info=True)
            resp.media = {"message": "Server Error!"}
            resp.status = falcon.HTTP_500
    


