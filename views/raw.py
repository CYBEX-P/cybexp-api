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
from resource.common import exception_handler, validate_org

def configureCacheDB(file_entries, fs):
    Raw.file_entries = file_entries
    Raw.fs = fs

class Raw(object):
    file_entries = None
    fs = None

    @exception_handler
    @validate_org
    def on_post(self, req, resp):
        org = req.context['org']
        
        info = {}
        info['timestamp'] = time.time()
        info['processed'] = False

        for part in req.media:
            if part.name == 'file':
                fdata = part.stream.read()
                fenc = encrypt_file(fdata)
                info['fid'] = self.fs.put(fenc, filename=part.filename)

            elif part.name in ['name', 'orgid', 'timezone', 'typetag']:
                info[part.name] = part.text

            else:
                resp.media = {"message": "Invalid input: " + part.name}
                resp.status = falcon.HTTP_400
                return

        if info['orgid'] != org._hash:
            resp.media = {"message": "Token does not belong to orgid!"}
            resp.status = falcon.HTTP_400
            return

        if 'timezone' not in info:
            info['timezone'] = "UTC"

        _ = self.file_entries.insert_one(info)
        resp.media = {"message" : "File uploaded successfully!"}
        resp.status = falcon.HTTP_201

    
