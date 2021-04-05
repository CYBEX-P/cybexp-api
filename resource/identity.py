"""api.resource.identity contains views for User and Org management."""

import falcon
import pdb

import tahoe

import loadconfig

from .common import ResourceBase, exception_handler, validate_token, \
    tahoe, Identity
from tahoe.identity.error import UserIsAdminError, UserIsInAclError, \
     UserIsNotInAclError, UserIsInOrgError, UserIsNotAdminError, \
     UserIsNotInOrgError, UserIsOnlyAdminError


class OrgAddUser(ResourceBase):

    @validate_token
    @exception_handler
    def on_post(self, req, resp):

        try:
            org_hash = req.media['org_hash']
            user_hash_list = req.media['user']
            add_to = req.media['add_to']
        except KeyError as e:
            resp.media = {"message": repr(e)}
            resp.status = falcon.HTTP_400
            return          

        user = req.context['user']
        
        org = Identity._backend.find_org(_hash=org_hash, parse=True)
        if org is None:
            resp.media = {"message": "Invalid org hash."}
            resp.status = falcon.HTTP_400
            return

        if not user.is_admin_of(org):
            resp.media = {"message": "You are not an admin of this org."}
            resp.status = falcon.HTTP_401
            return

        if isinstance(user_hash_list, str):
            user_hash_list = [user_hash_list]
        
        if isinstance(add_to, str):
            add_to = [add_to]
        if 'all' in add_to:
            add_to = 'admin'
        elif 'admin' in add_to:
            add_to = 'admin'
        elif 'user' in add_to:
            add_to = 'user'
        elif 'acl' in add_to:
            add_to = 'acl'
        else:
            resp.media = {"message": "Invalid 'add_to'!"}
            resp.status = falcon.HTTP_400
            return

        try:
            if add_to == 'admin':
                org.add_admin(user_hash_list)
            elif add_to == 'user':
                org.add_user(user_hash_list)
            elif add_to == 'acl':
                org.add_user_to_acl(user_hash_list)
        except (UserIsAdminError, UserIsInAclError, UserIsInOrgError) as e:
            resp.media = {"message": f"{e}"}
            resp.status = falcon.HTTP_400
            return
                
        resp.media = {"message": "User/s successfully added!"}
        resp.status = falcon.HTTP_201
        return


class OrgInfo(ResourceBase):

    @validate_token
    @exception_handler
    def on_post(self, req, resp):

        user = req.context['user']
        org_hash = req.media['org_hash']
        org = Identity._backend.find_org(_hash=org_hash, parse=True)

        if org is None:
            resp.media = {"message": "Invalid Org hash!"}
            resp.status = falcon.HTTP_400
            return

        if not user.is_admin_of(org):
            resp.media = {"message": "You are not an admin of this Org!"}
            resp.status = falcon.HTTP_401
            return

        return_type = req.media.get('return_type', ['all'])
        if isinstance(return_type, str):
            return_type = [return_type]

        if 'all' in return_type:
            return_type = ['admin', 'user', 'acl']

        result = {}
        
        for rt in return_type:
            if rt == 'admin':
                result['admin'] = [a.doc_no_pass for a in org.get_admins()]
            elif rt == 'user':
                result['user'] = [u.doc_no_pass for u in org.get_users()]
            elif rt == 'acl':
                result['acl'] = org._acl
            else:
                resp.media = {"message": f"Invalid return_type='{rt}'"}
                resp.status = falcon.HTTP_400
                return

        resp.media = {"result": result, "message": "See result."}
        resp.status = falcon.HTTP_200
        return


class OrgDelUser(ResourceBase):

    @validate_token
    @exception_handler
    def on_post(self, req, resp):

        try:
            org_hash = req.media['org_hash']
            user_hash_list = req.media['user']
            del_from = req.media['del_from']
        except KeyError as e:
            resp.media = {"message": repr(e)}
            resp.status = falcon.HTTP_400
            return          

        user = req.context['user']
        
        org = Identity._backend.find_org(_hash=org_hash, parse=True)
        if org is None:
            resp.media = {"message": "Invalid org hash!"}
            resp.status = falcon.HTTP_400
            return

        if not user.is_admin_of(org):
            resp.media = {"message": "You are not an admin of this org!"}
            resp.status = falcon.HTTP_401
            return

        if isinstance(user_hash_list, str):
            user_hash_list = [user_hash_list]
        
        if isinstance(del_from, str):
            del_from = [del_from]
        if 'all' in del_from:
            del_from = ['acl', 'user', 'admin']      

        for k in del_from:
            if k not in ['acl', 'user', 'admin']:                
                resp.media = {"message": "Invalid 'del_from'!"}
                resp.status = falcon.HTTP_400
                return
        
        try:
            if 'acl' in del_from:
                org.del_user_from_acl(user_hash_list)
            if 'user' in del_from:
                org.del_user(user_hash_list)
            if 'admin' in del_from:
                org.del_admin(user_hash_list)
            
        except (UserIsAdminError, UserIsNotAdminError, UserIsNotInAclError,
                UserIsNotInOrgError, UserIsOnlyAdminError) as e:
            resp.media = {"message": f"{e}"}
            resp.status = falcon.HTTP_400
            return
                
        resp.media = {"message": "User/s successfully deleted!"}
        resp.status = falcon.HTTP_201
        return


class OrgsAdminOf(ResourceBase):

    @validate_token
    @exception_handler
    def on_get(self, req, resp):
        user = req.context['user']
        r = user.orgs_admin_of()
        lst = list(r)

        resp.media = {"result": lst, "message": "See result."}
        resp.status = falcon.HTTP_200
        return


class OrgsUserOf(ResourceBase):

    @validate_token
    @exception_handler
    def on_get(self, req, resp):
        user = req.context['user']
        r = user.orgs_user_of()
        lst = list(r)

        resp.media = {"result": lst, "message": "See result."}
        resp.status = falcon.HTTP_200
        return


class UserInfoSelf(ResourceBase):

    @validate_token
    @exception_handler
    def on_get(self, req, resp):
        user = req.context['user']

        resp.media = {"result": user.doc_no_pass,
                      "message": "See result."}
        resp.status = falcon.HTTP_200
        return
    

##class RegisterUser(ResourceBase):
##    """Register/create user."""
##
##    @validate_token
##    @exception_handler
##    def on_post(self, req, resp):
##        """
##        Handles post requests.
##
##        Parameters
##        ----------
##        
##        """
##        
##        email = req.media.pop('email')
##        password = req.media.pop('password')
##        password2 = req.media.pop('password2')
##        name = req.media.pop('name')
##        
##        if password != password2:
##            resp.media = {"message" : "Passwords do not match!"}
##            resp.status = falcon.HTTP_400
##            return
##
##        try:
##            user = self._backend.create_user(email, password, name)
##
##            resp.media = {"message" : "User created",
##                         "email": user.email,
##                         "token": user.token}
##            resp.status = falcon.HTTP_201
##            return
##
##        except tahoe.identity.backend.DuplicateUserError:
##            resp.media = {"message" : "Username (email) already exists!"}
##            resp.status = falcon.HTTP_400
##            return


##    @ident_common.extract_request_data(required_fields=["email", "password","password2","name"])
##    @ident_common.validate_token
##    @ident_common.required_groups_any(required_groups_any=["system_register"])
##    @exception_handler
##    def registerUser(self, req, resp, request_data, **kwargs):
##        # print(request_data)
##        try:
##            # print("ident_backend:", self.ident_backend)
##            if not self.ident_backend.user_exists(request_data["email"]):
##                if request_data["password"] != request_data["password2"]:
##                    resp.media = {"message" : "Passwords must match"}
##                    resp.status = falcon.HTTP_400
##                    return
##                user = User(
##                                email=request_data["email"],
##                                password=request_data["password"],
##                                name=request_data["name"],
##                                # _backend=self.ident_backend
##                           )
##
##                resp.media = {"message" : "Created",
##                             "email": request_data["email"],
##                             "token":user.token}
##                resp.status = falcon.HTTP_201
##                return
##
##            else: # user exists
##                resp.media = {"message" : "User already exists"}
##                resp.status = falcon.HTTP_409
##                return
##        except:
##            # traceback.print_exc()
##            resp.media = {"message" : "Server Error"}
##            resp.status = falcon.HTTP_500
##            return














































'''

import falcon
import time
import logging
import pymongo
import traceback
import sys


# import loadconfig
# from . import crypto
from . import ident_common


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

    def on_get(self, req, resp):
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
    def on_get(self, req, resp):
        return self.get_my_hash(req,resp)

    #@ident_common.extract_request_data()
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


'''
