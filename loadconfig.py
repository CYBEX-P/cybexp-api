import logging, json, sys, os

# default config
default = { 
  "mongo_url" : "mongodb://localhost:27017/",
  "cache_db" : "cache_db",
  "report_db" : "report_db",
}

# read config from file config.json
try: 
  with open('config.json', 'r') as f:
    config = json.load(f)
except FileNotFoundError:
  config = loaddb.default
  logging.warning("No config file found, using default config")
except json.decoder.JSONDecodeError:
  print("Error in config -- check log file!")
  logging.error("Bad configuration file!", exc_info=True)
  sys.exit(1)


# Mongo DB Config
mongoconfig = config.pop("mongo")

# mongo_url is required, others optional
os.environ["CYBEXP_API_MONGO_URL"] = mongoconfig.pop("mongo_url")
os.environ["CYBEXP_API_CACHE_DB"] = mongoconfig.pop("cache_db", "cache_db")
os.environ["CYBEXP_API_REPORT_DB"] = mongoconfig.pop("report_db", "report_db")
