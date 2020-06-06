from pymongo import MongoClient

default = { 
  "mongo_url" : "mongodb://localhost:27017/",
  "cache_db" : "cache_db",
  "file_entries_coll" : "file_entries",
  "report_db" : "report_db",
  "query_coll" : "query",
  "report_coll" : "report"
}

# mongo_url is mandatory, others optional

def loaddb(config): 
  client = MongoClient(config['mongo_url'])

  # cache
  cache_db_name = config.get('cache_db', 'cache_db')
  cache_db = client.get_database(cache_db_name)

  # file entries collection
  file_entries_name = config.get('file_entries', 'file_entries')
  file_entries = cache_db.get_collection(file_entries_name)

  # grid fs file storage
  cfs = gridfs.GridFS(cache_db)

  # report db
  report_db_name = config.get('report_db', 'report_db')
  report_db = client.get_database(report_db_name)

  # query collection
  query_coll_name = config.get('query_coll', 'query_coll')
  query = report_db.get_collection(query_coll_name)

  # report collection
  report_coll_name = config.get('report_coll', 'report_coll')
  report = report_db.get_collection(report_coll_name)
  
  
  return file_entries, cfs, report, query
