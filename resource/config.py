import falcon
import time
import logging
import pymongo
import traceback
# import loadconfig
# from . import crypto

import sys
sys.path.insert(1, '/home/nacho/Projects/tahoe0.7-dev/')


import tahoe
from tahoe import NoBackend, Attribute, parse
from tahoe.identity import IdentityBackend, Identity, User, Org, InputConfig

from . import ident_common

# TODO change this URI to production 
ident_mongo_url = "mongodb://localhost"
# main_backend = MongoBackend(mongo_url="mongodb://localhost") # not needed

def has_all_keys(dic, keys):
    return all(required_key in dic for required_key in keys)


def user_hash_to_org_admin_list(backend, user_hash):
    orgs_is_admin = backend.find({"itype": "object", 
                                    "sub_type": "cybexp_org", 
                                    "_adm_ref": user_hash})
    direct_access = list()
    for org in orgs_is_admin:
       direct_access.append(org["_hash"]) 
    return direct_access



class AddConfig(object):
    def __init__(self, ident_backend):
        self.ident_backend = ident_backend #required by decorator
    def on_post(self, req, resp):
        return self.add_config(req,resp)

    @ident_common.extract_request_data(required_fields=["config","orgname"])
    @ident_common.validate_token
    @ident_common.get_org_object
    @ident_common.exception_handler
    def add_config(self, req, resp, request_data ,user_object, **kwargs):

        new_config = request_data["config"]

        if not isinstance(new_config, dict):
            resp.media = {"message" : "Bad configuration, look at documentation"}
            resp.status = falcon.HTTP_500
            return 

        min_req_keys = ["plugin","name","typetag","timezone","enabled"]

        if has_all_keys(new_config, min_req_keys):
            try:
                org_hash = ident_common.org_name_to_hash(self.ident_backend,request_data["orgname"])
                if not org_hash:
                    resp.media = {"message" : "Failed to add config for ORG(name={})".format(request_data["orgname"])}
                    resp.status = falcon.HTTP_403
                    return
                # check if user is an admin for the org in the request
                if org_hash in user_hash_to_org_admin_list(self.ident_backend, user_object._hash):
                    data = []
                    # add any extra config params to the config
                    for k in {x: new_config[x] for x in new_config if x not in min_req_keys}:
                        new_att = Attribute(k, new_config[k], _backend=self.ident_backend )
                        data.append(new_att)
                    
                    InputConfig(
                                    plugin=new_config["plugin"],
                                    name=new_config["name"],
                                    typetag=new_config["typetag"],
                                    orgid=org_hash,
                                    timezone=new_config["timezone"],
                                    data=data,
                                    enabled=new_config["enabled"],
                                    _backend=self.ident_backend
                                )
                    resp.media = {"message" : "created"}
                    resp.status = falcon.HTTP_200
                    return
                else:
                    resp.media = {"message" : "Failed to add config for ORG(name={})".format(request_data["orgname"])}
                    resp.status = falcon.HTTP_403
                    return
                
            except:
                traceback.print_exc()
                # logging.exception("Bad config")
                resp.media = {"message" : "bad configuration"}
                resp.status = falcon.HTTP_400
                return
        # except:
        #     # logging.exception("Bad config")
        #     resp.media = {"message" : "bad configuration, 'config' argument must be dict with the following and any additional information: "+str(min_req_keys)}
        #     resp.status = falcon.HTTP_400
        #     return


# class EnableConfig(object):
#     @tokenManager._extract_request_data(required_fields=["config_hash"])
#     @tokenManager._validate_token
#     def on_post(self, req, resp, request_data ,user_object, **kwargs):
#         pass

