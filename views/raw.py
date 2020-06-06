if __name__ in ["__main__", "raw"]:
  from crypto import encrypt_file
else:
  from .crypto import encrypt_file

import os, falcon, gridfs, pymongo, time, logging

# === Debug ===
import pdb, pprint

# Cache Data Lake (Mongo DB)

def loadcachedb():
  mongo_url = os.getenv("CYBEXP_API_MONGO_URL")
  cache_db = os.getenv("CYBEXP_API_CACHE_DB", "cache_db")

  client = pymongo.MongoClient(mongo_url)
  cache_db = client.get_database(cache_db)

  file_entries = cache_db.file_entries
  cfs = gridfs.GridFS(cache_db)

  return file_entries, cfs

# Raw Class

class Raw(object):
  file_entries, fs = loadcachedb()
  
  def on_post(self, req, resp):
    try:
    
      info = {}
      info['timestamp'] = time.time()
      info['processed'] = False

      for part in req.media:
        if part.name == 'orgid': info['orgid'] = part.text
        elif part.name == 'typtag': info['typtag'] = part.text
        elif part.name == 'timezone': info['timezone'] = part.text
        elif part.name == 'file':
          fenc = encrypt_file(part.stream.read())
          info['fid'] = self.fs.put(fenc, filename=part.filename)
        else:
          resp.media, resp.status = {"message":"Invalid input "+part.name}, falcon.HTTP_400

      if not all(key in info for key in ['orgid', 'typtag', 'timezone', 'fid']):
        resp.media, resp.status = {"message":"Incomplete input"}, falcon.HTTP_400
        if 'fid' in info and self.fs.exists(info['fid']): self.fs.delete(fid)
        return              

      _ = self.file_entries.insert_one(info)
      resp.media, resp.status = {"message" : "File Uploaded Successfully"}, falcon.HTTP_201
      
    except falcon.errors.HTTPBadRequest as err:
      resp.media, resp.status = {"message" : "Invalid raw input! " + repr(err) + str(err)}, falcon.HTTP_400
      
    except pymongo.errors.ServerSelectionTimeoutError:
      logging.exception("api.views.raw.Raw -- Cache data lake down!")
      resp.media, resp.status = {"message" : "Database down!"}, falcon.HTTP_500
      
    except:
      logging.exception("api.views.raw.Raw")
      resp.media, resp.status = {"message" : "Server Error!"}, falcon.HTTP_500
    
    
