import falcon
import time
import logging
import pymongo

if __name__ != 'api.views.query':
    import os, sys
    J = os.path.join
    sys.path = ['..', J('..', '..')] + sys.path
    del os, sys

import loadconfig

from .crypto import encrypt_file
from resource.common import Identity, exception_handler, validate_user


def configureCacheDB(file_entries, fs):
    """api.py calls this to configure Cache DB parameters."""
    
    Raw.file_entries = file_entries
    Raw.fs = fs
    

class Raw(object):
    "Handles /raw endpoint."""
    
    file_entries = None
    fs = None

    @exception_handler
    @validate_user
    def on_post(self, req, resp):
        user = req.context['user']
        
        info = {}
        info['timestamp'] = time.time()
        info['processed'] = False

        fenc = None
        for part in req.media:
            if part.name == 'file':
                fdata = part.stream.read()
                fenc = encrypt_file(fdata)
            elif part.name in ['name', 'orgid', 'timezone', 'typetag']:
                info[part.name] = part.text
            else:
                resp.media = {"message": "Invalid input: " + part.name}
                resp.status = falcon.HTTP_400
                return
        
        orgid = info['orgid']
        org = Identity._backend.find_org(_hash=orgid, parse=True)
        if org is None:
            org = Identity._backend.find_org(orgname=orgid, parse=True)
            if org is None:
                resp.media = {"message": f"Invalid 'orgid'={orgid}!"}
                resp.status = falcon.HTTP_400
                return
            info['orgid'] = org._hash

        if not user.is_admin_of(org):
            resp.media = {"message": "You are not an admin of this org!"}
            resp.status = falcon.HTTP_401
            return

        # Required Keys
        for key in ['name', 'typetag']:
            _ = info[key]

        if 'timezone' not in info:
            info['timezone'] = "UTC"

        if fenc is None:
            resp.media = {"message": "Invalid or missing file!"}
            resp.status = falcon.HTTP_400
            return

        info['fid'] = self.fs.put(fenc, filename=part.filename)
        _ = self.file_entries.insert_one(info)
        
        resp.media = {"message" : "File uploaded successfully!"}
        resp.status = falcon.HTTP_201








    
