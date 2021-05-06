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
        info = {}
        info['timestamp'] = time.time()
        info['processed'] = False

        info['typetag'] = req.media.pop('typetag')
        info['name'] = req.media.pop('name')

        org = req.context['org']
        info['orgid'] = req.media.pop('orgid')
        if info['orgid'] != org._hash:
            resp.media = {"message": "Token does not belong to orgid!"}
            resp.status = falcon.HTTP_400
            return

        timezone = req.media.pop('timezone', None)
        if timezone is None:
            timezone = "UTC"
        info['timezone'] = timezone

        file = req.media.pop('file')
        fenc = encrypt_file(file.stream.read())
        info['fid'] = self.fs.put(fenc, filename=part.filename)

        _ = self.file_entries.insert_one(info)
        resp.media = {"message" : "File uploaded successfully!"}
        resp.status = falcon.HTTP_201

    
