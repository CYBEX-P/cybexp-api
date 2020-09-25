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

from .identity import TokenManager

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

    tokenManager = TokenManager(ident_mongo_url)
    ident_mongo_url = ident_mongo_url
    ident_backend = IdentityBackend(mongo_url=ident_mongo_url, create=False)

    @tokenManager._extract_request_data(["config"])
    @tokenManager._validate_token
    def on_post(self, req, resp, request_data ,user_object, **kwargs):

        new_config = request_data["config"]

        if not isinstance(new_config, dict):
            resp.media = {"message" : "Bad configuration, look at documentation"}
            resp.status = falcon.HTTP_500
            return 

        min_req_keys = ["plugin","name","typetag","orgid","timezone","enabled"]

        if has_all_keys(new_config, min_req_keys):
            try:
                # check if user is an admin for the org in the request
                if new_config["orgid"] in user_hash_to_org_admin_list(self.ident_backend, user_object._hash):
                    data = []
                    # add any extra config params to the config
                    for k in {x: new_config[x] for x in new_config if x not in min_req_keys}:
                        new_att = Attribute(k, new_config[k], _backend=self.ident_backend )
                        data.append(new_att)

                    InputConfig(
                                    plugin=new_config["plugin"],
                                    name=new_config["name"],
                                    typetag=new_config["typetag"],
                                    orgid=new_config["orgid"],
                                    timezone=new_config["timezone"],
                                    data=data,
                                    enabled=new_config["enabled"],
                                    _backend=self.ident_backend
                                )
                else:
                    resp.media = {"message" : "Must be admin of the org({}) to be able to add configurations".format(new_config["orgid"])}
                    resp.status = falcon.HTTP_400
                    return
                
            except:
                # logging.exception("Bad config")
                resp.media = {"message" : "bad configuration"}
                resp.status = falcon.HTTP_400
                return
        # except:
        #     # logging.exception("Bad config")
        #     resp.media = {"message" : "bad configuration, 'config' argument must be dict with the following and any additional information: "+str(min_req_keys)}
        #     resp.status = falcon.HTTP_400
        #     return


# class EnableConfig(object, UserManager):
#     @tokenManager._extract_request_data(required_fields=["config_hash"])
#     @tokenManager._validate_token
#     def on_post(self, req, resp, request_data ,user_object, **kwargs):
#         pass


# class TokenManager(object):

#     def __init__(self, ident_mongo_url="mongodb://localhost"):
#         self.token_checker = Identity(
#                                     sub_type="_invalid_type",
#                                     data=[Attribute("_invalid_att",False, _backend=NoBackend())],
#                                     _backend=NoBackend()
#                                 )

#         self.ident_backend = IdentityBackend(mongo_url=ident_mongo_url, create=False)
#         Identity._backend = self.ident_backend # todo BUG; if there are multiple of TOkenManager, this will not work correclty


#     def get_payload(self, token):


#     def hash_to_user(self, usr_hash):

#     def _is_token_revoked(self,token):


#     def _validate_token(func):

#     def _extract_request_data(required_fields:list=[]):

        
#     def on_post(self, req, resp, var1,var2=None, **kwargs):
#         # default return
#         # resp.media = {"message" : "404 Not Found"} # more authentic without body
#         resp.status = falcon.HTTP_404

#         try:
#             path = req.path
#             print("Path:", path)
#             print("var1:",var1)
#             print("var2:",var2)

#             if var1 == "register":
#                 print("registering")
#                 return self.registerUser(req, resp)

#             elif var1 == "login":
#                 print("logging in")
#                 # return self.login(req, resp)

#             elif var1 == "token-test":
#                 print("checking token")
#                 # return self.token_test(req, resp)

#             elif var1 == "logout":
#                 return self.logout(req, resp)

#             elif var1 == "create" and var2 != None:
#                 print("creating ", "")
#                 if var2 == "user":
#                     print("user")
#                     return self.registerUser(req, resp)

#                 elif var2 == "org":
#                     print("org")
#                     # return self.addOrg(req, resp)


#             elif var1 == "debug" and var2 != None:
#                 print("debug ", "")
#                 if var2 == "test":
#                     print("running test endpoint")
#                     return self.test(req, resp)

#             else:
#                 resp.media = {"message" : "404 Not Found"}
#                 resp.status = falcon.HTTP_404
#                 return

          
#         except falcon.errors.HTTPBadRequest as err:
#               resp.media = {"message" : "Invalid input! " +
#                             repr(err) + str(err)}
#               resp.status = falcon.HTTP_400
#               return
          
#         except pymongo.errors.ServerSelectionTimeoutError:
#             logging.exception("Backend down")
#             resp.media = {"message" : "backend down"}
#             resp.status = falcon.HTTP_500
#             return

#         except (KeyboardInterrupt, SystemExit):
#             raise
          
#         except:
#             logging.exception("[API] TokenManager", exc_info=True)
#             resp.media = {"message" : "Server Error!"}
#             resp.status = falcon.HTTP_500
#             return


#     @_validate_token
#     def token_test(self, req, resp, user_object, **kwargs):

#     @_extract_request_data(required_fields=["email", "password"])
#     def login(self, req, resp, request_data, **kwargs):


#     @_validate_token
#     def logout(self, req, resp, **kwargs):
#         # revoke key
#         raise Exception("TODO; logout not implemented")
#         pass

#     @_extract_request_data(required_fields=["email", "password","password2","name"])
#     def registerUser(self, req, resp, request_data, **kwargs):


#     @_validate_token
#     def addOrg(self, req, resp, **kwargs):
#         raise Exception("TODO; add org not implemented")
#         pass



#     # GOOD example, call extract then validate

#     @_extract_request_data(required_fields=["email"])
#     # @_extract_request_data()
#     @_validate_token
#     def test(self, req, resp, request_data, **kwargs):
#         print("req data:", request_data)
#         resp.media = {"message" : "it worked"}
#         resp.status = falcon.HTTP_200
#         return


