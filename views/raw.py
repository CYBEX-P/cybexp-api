import falcon
import time
import logging
import pymongo

import loadconfig
from . import crypto

class Raw(object):
    file_entries, fs = loadconfig.get_cache_db()

    def on_post(self, req, resp):
        try:

            info = {}
            info['timestamp'] = time.time()
            info['processed'] = False

            for part in req.media:
                if part.name == 'file':
                    fenc = crypto.encrypt_file(part.stream.read())
                    info['fid'] = self.fs.put(fenc, filename=part.filename)
                elif part.name in ['typetag', 'name', 'orgid', 'timezone']:
                    info[part.name] = part.text
                else:
                    resp.media = {"message": "Invalid input: " + part.name}
                    resp.status = falcon.HTTP_400
                    return

            required_keys = ['typetag', 'name', 'orgid', 'timezone', 'fid']
            if not all(key in info for key in required_keys):
                resp.media = {"message": "Incomplete input"}
                resp.status = falcon.HTTP_400
                if 'fid' in info and self.fs.exists(info['fid']):
                    self.fs.delete(info['fid'])
                return              

            _ = self.file_entries.insert_one(info)
            resp.media = {"message" : "File Uploaded Successfully"}
            resp.status = falcon.HTTP_201
          
        except falcon.errors.HTTPBadRequest as err:
              resp.media = {"message" : "Invalid raw input! " +
                            repr(err) + str(err)}
              resp.status = falcon.HTTP_400
          
        except pymongo.errors.ServerSelectionTimeoutError:
            logging.exception("Cache data lake down")
            resp.media = {"message" : "Database down"}
            resp.status = falcon.HTTP_500

        except (KeyboardInterrupt, SystemExit):
            raise
          
        except:
            logging.exception("raw", exc_info=True)
            resp.media = {"message" : "Server Error!"}
            resp.status = falcon.HTTP_500

    
