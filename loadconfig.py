"""Read config.json file and initialize database or Tahoe Backend."""

import collections.abc
import gridfs
import json
import logging
import os
import pdb
import pymongo
import sys

import tahoe


default = {
    "analytics": { 
        "mongo_url": "mongodb://localhost:27017/",
        "db": "analytics_db",
        "coll": "instance",
    },
    "archive": { 
        "mongo_url": "mongodb://localhost:27017/",
        "db": "tahoe_db",
        "coll": "instance",
    },
    "cache": {
        "mongo_url": "mongodb://localhost:27017/",
        "db": "cache_db",
        "coll": "file_entries"
    },
    "identity": {
        "mongo_url": "mongodb://localhost:27017/",
        "db": "identity_db",
        "coll": "instance"
    },
    "report": {
        "mongo_url": "mongodb://localhost:27017/",
        "db": "report_db",
        "coll": "instance"
    },
    "tahoe": {
        "mongo_url": "mongodb://localhost:27017/",
        "db": "tahoe_db",
        "coll": "instance"
    }
}

def update(d, u):
    "Recursively update nested dictionary."
    
    for k, v in u.items():
        if isinstance(v, collections.abc.Mapping):
            d[k] = update(d.get(k, {}), v)
        else:
            d[k] = v
    return d

def get_config(filename='config.json', db='all'):
    """
    Read config from file `config.json`.
    Any config values missing will be substituted with the corresponding default value.

    Raises
    ------
    FileNotFoundError
        configuration will eniterly be default config.
    JSONDecodeError
        Bad configuration file logging error, system exits.
    
    Return
    ------
    config: Dictionary
        configuration values

        
    """
  
    try:
        this_dir = os.path.dirname(__file__)
        filename = os.path.join(this_dir, filename)
        with open(filename, 'r') as f:
            config = json.load(f)
    except FileNotFoundError:
        config = default
        logging.warning("No config file found, using default config")
    except json.decoder.JSONDecodeError:
        logging.error("Bad configuration file!", exc_info=True)
        sys.exit(1)  # 1 = error in linux

    update(config, default)

    if db != 'all':
        if db not in ('archive', 'cache', 'identity', 'report', 'tahoe'):
            logging.error(f"Invalid db name '{db}'!", exc_info=True)
            sys.exit(1)

        config = config[db]

    return config

def get_cache_db(filename='config.json'):
    cacheconfig = get_config(filename, 'cache')
    mongo_url = cacheconfig['mongo_url']
    dbname = cacheconfig['db']
    collname = cacheconfig['coll']
    
    client = pymongo.MongoClient(mongo_url, connect=False)
    db = client.get_database(dbname)
    coll = db.get_collection(collname)
    fs = gridfs.GridFS(db)

    return coll, fs

def get_backend(filename='config.json', db='tahoe'):
    reportconfig = get_config(filename, db)
    mongo_url = reportconfig['mongo_url']
    dbname = reportconfig['db']
    collname = reportconfig['coll']
    backend = tahoe.MongoBackend(mongo_url, dbname, collname)
    return backend

def get_analytics_backend(filename='config.json'):
    """
    Retrieves the analytics backend identity for the API 
    """
    return get_backend(filename, db='analytics')

def get_archive_backend(filename='config.json'):
    """
    Retrieves the archive backend identity for the API 
    """
    return get_backend(filename, db='archive')

def get_report_backend(filename='config.json'):
    """
    Retrieves the report backend identity for the API 
    """
    return get_backend(filename, db='report')

def get_tahoe_backend(filename='config.json'):
    """
    Retrieves the tahoe backend identity for the API 
    """
    return get_backend(filename, db='tahoe')




    

##def get_config(filename='config.json'):
##    """Read config from file `config.json`."""
##  
##    try:
##        this_dir = os.path.dirname(__file__)
##        filename = os.path.join(this_dir, filename)
##        with open(filename, 'r') as f:
##            config = json.load(f)
##    except FileNotFoundError:
##        config = default
##        logging.warning("No config file found, using default config")
##    except json.decoder.JSONDecodeError:
##        logging.error("Bad configuration file!", exc_info=True)
##        sys.exit(1) # 1 = error in linux
##
##    for k, v in default.items():
##        if k not in config:
##            config[k] = v
##
##    return config
##
##
##def get_archiveconfig(filename='config.json'):
##    """Configuration of Identity Backend."""
##  
##    config = get_config(filename)
##    archiveconfig = config['archive']
##    for k, v in default['archive'].items():
##        if k not in archiveconfig:
##            archiveconfig[k] = v
##    return archiveconfig
##      
##
##def get_apiconfig(filename='config.json'):
##    """Configuration of API."""
##    
##    config = get_config(filename)
##    apiconfig = config['api']
##    
##    for k, v in default['api'].items():
##        if k not in apiconfig:
##            apiconfig[k] = v
##    return apiconfig
##        
##
##def get_identity_backend(filename='config.json'):
##    identityconfig = get_identityconfig(filename)
##    mongo_url = identityconfig['mongo_url']
##    dbname = identityconfig['identity_db']
##    collname = identityconfig['identity_coll']
##    backend = tahoe.identity.IdentityBackend(mongo_url, dbname, collname)
##    return backend
##

##
##def get_tahoe_backend(filename='config.json'):
##    archiveconfig = get_archiveconfig(filename)
##    mongo_url = archiveconfig['mongo_url']
##    dbname = archiveconfig['tahoe_db']
##    collname = archiveconfig['tahoe_coll']
##    backend = tahoe.MongoBackend(mongo_url, dbname, collname)
##    return backend
##
##get_archive_backend = get_tahoe_backend
##
####def get_archive_backend(filename='config.json'):
####    archiveconfig = get_archiveconfig(filename)
####    mongo_url = archiveconfig['mongo_url']
####    dbname = archiveconfig['archive_db']
####    collname = archiveconfig['archive_coll']
####    backend = tahoe.MongoBackend(mongo_url, dbname, collname)
####    return backend
##
##def get_cacheconfig(filename='config.json'):
##    """Configuration of Identity Backend."""
##  
##    config = get_config(filename)
##    archiveconfig = config['cache']
##    for k, v in default['cahce'].items():
##        if k not in archiveconfig:
##            archiveconfig[k] = v
##    return archiveconfig
##
##























