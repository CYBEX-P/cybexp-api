import falcon
import time
import logging
import pymongo
import traceback
import sys


# import loadconfig
# from . import crypto
from . import ident_common
sys.path.insert(1, '/home/nacho/Projects/tahoe0.7-dev/')


import tahoe
from tahoe import NoBackend, Attribute, parse
from tahoe.identity import IdentityBackend, Identity, User, Org



if __name__ == '__main__':
    ident_mongo_url="mongodb://localhost"
    idnt_bnd = IdentityBackend(mongo_url=ident_mongo_url, create=False)
    Identity._backend = idnt_bnd 
# else:
    # todo load config
    # print("TODO: implement loadconfig")
    # sys.exit(1)


class TokenTest(object):
    def __init__(self, ident_backend):
        self.ident_backend = ident_backend #required by decorator

    def on_post(self, req, resp):
        return self.token_test(req,resp)

    # @ident_common.extract_request_data() # for now validate token uses this
    @ident_common.validate_token
    @ident_common.exception_handler
    def token_test(self, req, resp,user_object, token, **kwargs):
        try:
            resp.media = {"message" : "Token valid", "token":token}
            resp.status = falcon.HTTP_200
            return
        except:
            traceback.print_exc()

            resp.media = {"message" : "401 Unauthorized"}
            resp.status = falcon.HTTP_401
            return

class Login(object):
    def __init__(self, ident_backend):
        self.ident_backend = ident_backend #required by decorator
    def on_post(self, req, resp):
        return self.login(req,resp)

    @ident_common.extract_request_data(required_fields=["email", "password"])
    @ident_common.exception_handler
    def login(self, req, resp, request_data, **kwargs):
        if self.ident_backend.user_exists(request_data["email"]):
            user_hash = User(request_data["email"], _backend=NoBackend())._hash
            user = ident_common.hash_to_user(self.ident_backend,user_hash)
            # check pass
            correct_pass = user.checkpass(request_data["password"])
            if correct_pass:
                # todo return token in header as well
                tok = user.token
                resp.media = {"message" : "Login Successful", "token":tok}
                resp.status = falcon.HTTP_200
                return

            else: #incorrect pass
                resp.media = {"message" : "401 Unauthorized"}
                resp.status = falcon.HTTP_401
                return
        else: # user does not exist
            resp.media = {"message" : "401 Unauthorized"}
            resp.status = falcon.HTTP_401
            return



class Logout(object):
    def __init__(self, ident_backend):
        self.ident_backend = ident_backend #required by decorator
    def on_post(self, req, resp):
        return self.logout(req,resp)

    @ident_common.extract_request_data(required_fields=["email", "password"])
    @ident_common.validate_token
    @ident_common.exception_handler
    def logout(self, req, resp, **kwargs):
        # revoke key
        raise Exception("TODO; logout not implemented")
        pass


class RegisterUser(object):
    def __init__(self, ident_backend):
        self.ident_backend = ident_backend #required by decorator
    def on_post(self, req, resp):
        return self.registerUser(req,resp)

    @ident_common.extract_request_data(required_fields=["email", "password","password2","name"])
    # @ident_common.validate_token
    # @ident_common.required_groups_any(required_groups_any=["system_register"])
    @ident_common.exception_handler
    def registerUser(self, req, resp, request_data, **kwargs):
        # print(request_data)
        try:
            # print("ident_backend:", self.ident_backend)
            if not self.ident_backend.user_exists(request_data["email"]):
                if request_data["password"] != request_data["password2"]:
                    resp.media = {"message" : "Passwords must match"}
                    resp.status = falcon.HTTP_400
                    return
                user = User(
                                email=request_data["email"],
                                password=request_data["password"],
                                name=request_data["name"],
                                # _backend=self.ident_backend
                           )

                resp.media = {"message" : "Created",
                             "email": request_data["email"],
                             "token":user.token}
                resp.status = falcon.HTTP_201
                return

            else: # user exists
                resp.media = {"message" : "User already exists"}
                resp.status = falcon.HTTP_409
                return
        except:
            # traceback.print_exc()
            resp.media = {"message" : "Server Error"}
            resp.status = falcon.HTTP_500
            return

class RegisterOrg(object):
    def __init__(self, ident_backend):
        self.ident_backend = ident_backend #required by decorator
    def on_post(self, req, resp):
        return self.addOrg(req,resp)

    @ident_common.extract_request_data(required_fields=["orgname", "user","admin","name"])
    @ident_common.validate_token
    # @ident_common.required_groups_any(required_groups_any=["system_register"])
    @ident_common.exception_handler
    def addOrg(self, req, resp, request_data, user_object, **kwargs):      
        if not all(isinstance(request_data[k], list) for k in ["user", "admin"]):
            resp.media = {"message" : "'user' and 'admin' must be a list containing user hashses"}
            resp.status = falcon.HTTP_400
            return

        try:
            if not self.ident_backend.org_exists(request_data["orgname"]):
                org = Org(
                                orgname=request_data["orgname"],
                                user=request_data["user"],
                                admin=request_data["admin"],
                                name=request_data["name"]
                                # _backend=self.ident_backend
                           )

                resp.media = {
                                "message" : "Created",
                                "orgname" : request_data["orgname"],
                                "user" : request_data["user"],
                                "admin" : request_data["admin"],
                                "name" : request_data["name"],
                                "org_hash" : org._hash
                            }
                resp.status = falcon.HTTP_201
                return

            else: # user exists
                resp.media = {"message" : "Organization already exists"}
                resp.status = falcon.HTTP_409
                return
        except:
            traceback.print_exc()
            resp.media = {"message" : "Server Error"}
            resp.status = falcon.HTTP_500
            return



class ChangeACL(object):
    def __init__(self, ident_backend):
        self.ident_backend = ident_backend #required by decorator
    def on_post(self, req, resp):
        return self.change_org_acl(req,resp)

    @ident_common.extract_request_data(required_fields=["orgname", "acl"])
    @ident_common.validate_token
    @ident_common.get_org_object
    @ident_common.exception_handler
    def change_org_acl(self, req, resp, request_data, user_object,org_object, **kwargs):

        try:
            # checks if admin, else returns false. bad data raises
            worked = org_object.set_acl(user_object._hash,request_data["acl"])
            if worked:
                resp.media = {"message" : "Modified to: {}".format(request_data["acl"])}
                resp.status = falcon.HTTP_200
                return
            else:
                resp.media = {"message" : "Forbidden"}
                resp.status = falcon.HTTP_403
        except TypeError:
            traceback.print_exc()
            resp.media = {"message" : "ACL must be a list of user hashses"}
            resp.status = falcon.HTTP_400
            return


class GetMyHash(object):
    def __init__(self, ident_backend):
        self.ident_backend = ident_backend #required by decorator
    def on_post(self, req, resp):
        return self.get_my_hash(req,resp)

    @ident_common.extract_request_data()
    @ident_common.validate_token
    @ident_common.exception_handler
    def get_my_hash(self, req, resp, user_object, **kwargs):

        try:
            resp.media = {
                    "message" : "ok",
                    "_hash": user_object._hash
                }
            resp.status = falcon.HTTP_200
            return

        except:
            resp.media = {"message" : "Internal Error"}
            resp.status = falcon.HTTP_500
            return





    # def orgs_i_belong(self, req, resp, **kwargs):
    #     pass


    # def orgs_i_admin(self, req, resp, **kwargs):
    #     pass




# todo 
# add change password
# add list orgs
# add get my hash
# get orgs acl
# get orgs user list 
# get orgs admin list