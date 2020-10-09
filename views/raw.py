import falcon
import time
import logging
import pymongo

import loadconfig
from . import crypto

#where we input data

class Raw(object):
    """
    'Raw' is a class that works as the front line of the API.
    When called, it pulls the database config information and issues a timestamp index.
    The 'Raw' object then takes raw unfiltered data that is passed to it by the input database calling the on_post() function.
    That data is then scanned for indicated fields and then sent to the cache database.

    Attributes
    ----------
    file_entries: cache database reference
        Responsible for timestamping the data entry and sending the Input Config and raw data to the cache database provided 
        it passes the check for all required keys being present
    
    fs: cache database reference to the fs
        Responsible for handling the raw data and deleting the contents of the 'info' if the input does not pass the required
        keys check
    
    r:  timestamp reference
        Holds the timestamp
        


    """
    file_entries, fs = loadconfig.get_cache_db() 
    r = file_entries.create_index("timestamp")

    def on_post(self, req, resp):
        """
        Handles the posting of new raw unfiltered data and then sends it to the cache database.

        Parameters
        ----------
        req: Input Config Object
            The Input Configuration object. Mandatory values include:
            'typetag', 'name', 'orgid', 'timezone', 'fid' along with the unfiltered data.
        
        resp: Falcon Request Object
            Handles the HTTP API responses


        Raises
        ------
        falcon.errors.HTTPBadRequest
            Invalid or Incorrect raw input
       
        pymongo.errors.ServerSelectionTimeoutError
            Cache data lake is down
        
        KeyboardInterrupt
            Exit the system
        
        General Exception
            Server Error

        """
        try:

            info = {}
            info['timestamp'] = time.time()
            info['processed'] = False

            for part in req.media:
                if part.name == 'file':
                    fenc = crypto.encrypt_file(part.stream.read())
                    info['fid'] = self.fs.put(fenc, filename=part.filename) 
                elif part.name in ['typetag', 'name', 'orgid', 'timezone','config_hash']:
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

    
