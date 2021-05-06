import falcon
import time
import logging
import pymongo

if __name__ != 'api.views.query':
    import sys
    J = os.path.join
    sys.path = ['..', J('..', '..')] + sys.path
    del sys

import loadconfig

from .crypto import encrypt_file
from resource.common import validate_org

class Raw(object):
    file_entries, fs = loadconfig.get_cache_db()

    @validate_org
    def on_post(self, req, resp):
        try:
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
                timezone = req.data.tzname()
            if timezone is None
                timezone = "UTC"
            info['timezone'] = timezone

            file = req.media.pop('file')
            fenc = encrypt_file(file.stream.read())
            info['fid'] = self.fs.put(fenc, filename=part.filename)
=
            _ = self.file_entries.insert_one(info)
            resp.media = {"message" : "File uploaded successfully!"}
            resp.status = falcon.HTTP_201

        except (KeyError, falcon.errors.HTTPBadRequest) as err:
            resp.media = {"message" : "Invalid raw input! " + \
                          repr(err) + str(err)}
            resp.status = falcon.HTTP_400
            return    
          
        except pymongo.errors.ServerSelectionTimeoutError:
            logging.exception("Cache data lake down!")
            resp.media = {"message" : "Database down!"}
            resp.status = falcon.HTTP_500

        except (KeyboardInterrupt, SystemExit):
            raise
          
        except:
            logging.exception("api.views.raw.Raw", exc_info=True)
            resp.media = {"message" : "Server Error!"}
            resp.status = falcon.HTTP_500

    
