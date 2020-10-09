import falcon
import hashlib
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
    """
    handles incoming querys that are requested from the user
    
    Attributes
    ----------
    report_backend:
        The backend identity that the query will be sent towards. The identity it pulled from the API loadconfig file
        Default: localhost backend identity
    """
    report_backend = _BACKEND
  
    def on_post(self, req, resp):
        """
        Attempts to extract the itype and data from the passed 'req'. If those two types are in the incorrect
        formatting when passed, a bad request is raised along with an HTTP 400 response. Otherwise, A session
        JSON web token is generated and the data gets canonically interpreted as it is currently untrusted data;
        that canonical data then gets it's own hash generated in sha256. The untrusted data then gets encrypted
        from an encyption function call from the crypto view.

        Once the data has been encrypted, the web token, encoded data, data hash, and data itype get passed into
        a new Tahoe data structure TDQL. The API will then prompt if the report is ready or to come back later on
        the state of the query report.

        Parameters
        ----------
        req: Dict of string values
            Holds the 
        resp: Falcon Object
            Handles the HTTP API responses

        Raises
        ------
        KeyError, falcon.errors.HTTPBadRequest:
            Invalid query format of the values in the passed 'req' data
        
        Server Error:
            Server response stemming from an unconditional error
        """
        try:
            try:
                qtype = req.media.pop('type')
                qdata = req.media.pop('data')
            except (KeyError, falcon.errors.HTTPBadRequest) as err:
                resp.media = {"message" : "Invalid query format! " + \
                              repr(err) + str(err)}
                resp.status = falcon.HTTP_400
                return     
      
            userid = "identity--2b419244-b973-4d6e-94c5-378db82d8efa" # placeholder, replace with PyJWT
      
            canon_qdata = canonical(qdata).encode()
            qhash = hashlib.sha256(canon_qdata).hexdigest()
        
            enc_qdata = str(encrypt_file(canon_qdata))
            
            query = TDQL(qtype, enc_qdata, qhash, userid, time.time())
          
            if query.status == 'ready':
                report = self.report_backend.find_one(
                    {'_hash': query.report_id}, {'_id': 0})
                resp.media = report
                resp.status = falcon.HTTP_201
                return
              
            elif query.status == 'processing':
                resp.status = falcon.HTTP_202
                resp.media = {"message":"check back later",
                              "status":"processing"}
                return
            
            if os.name in ['nt', 'posix']:
                sock = socket.socket()
                sock.bind(('', 0))  
                host, port = sock.getsockname()
                nonce = secrets.token_hex(16)      # password # encrypt nonce
                sock.settimeout(15)                # 5 seconds
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
            resp.media = {"message":"Server Error!"}
            resp.status = falcon.HTTP_500
    


