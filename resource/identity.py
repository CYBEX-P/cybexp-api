"""api.resource.identity contains views for User and Org management."""

import falcon
import pdb

import tahoe

import loadconfig

from .common import ResourceBase, exception_handler, validate_user, \
    tahoe, Identity
from tahoe.identity.error import AdminIsNotUserError, InvalidUserHashError, \
     OrgExistsError, \
     UserExistsError, UserIsAdminError, UserIsInAclError, \
     UserIsNotInAclError, UserIsInOrgError, UserIsNotAdminError, \
     UserIsNotInOrgError, UserIsOnlyAdminError


class CreateOrg(ResourceBase):
    """Register/create Org."""

    @validate_user
    @exception_handler
    def on_post(self, req, resp):

        superuser = req.context['user']

        try:
            orgname = req.media['orgname']
            user = req.media['user']
            admin = req.media['admin']
            name = req.media['name']
        except KeyError as e:
            resp.media = {"message": repr(e)}
            resp.status = falcon.HTTP_400
            return      

        try:
            org = superuser.create_org(orgname, user, admin, name)
        except AttributeError:
            resp.media = {"message" : "Only CYBEX-P admin can create org!"}
            resp.status = falcon.HTTP_401
            return
        except (OrgExistsError, AdminIsNotUserError) as e:
            resp.media = {"message" : str(e)}
            resp.status = falcon.HTTP_400
            return
        else:
            resp.media = {"message" : "Org created!",
                         "result": org.doc}
            resp.status = falcon.HTTP_201
            return


class CreateUser(ResourceBase):
    """Register/create user."""

    @validate_user
    @exception_handler
    def on_post(self, req, resp):

        superuser = req.context['user']

        try:
            email = req.media['email']
            password = req.media['password']
            password2 = req.media['password2']
            name = req.media['name']
        except KeyError as e:
            resp.media = {"message": repr(e)}
            resp.status = falcon.HTTP_400
            return      
        
        if password != password2:
            resp.media = {"message" : "Passwords do not match!"}
            resp.status = falcon.HTTP_400
            return

        try:
            user = superuser.create_user(email, password, name)
        except AttributeError:
            resp.media = {"message" : "Only CYBEX-P admin can create user!"}
            resp.status = falcon.HTTP_401
            return
        except UserExistsError as e:
            resp.media = {"message" : str(e)}
            resp.status = falcon.HTTP_400
            return
        else:
            resp.media = {"message" : "User created!",
                         "result": user.doc_no_pass,
                         "token": user.token}
            resp.status = falcon.HTTP_201
            return


class OrgAddUser(ResourceBase):

    @validate_user
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
        except (UserIsAdminError, UserIsInAclError,
                UserIsInOrgError, InvalidUserHashError) as e:
            resp.media = {"message": f"{e}"}
            resp.status = falcon.HTTP_400
            return
                
        resp.media = {"message": "User/s successfully added!"}
        resp.status = falcon.HTTP_201
        return


class OrgInfo(ResourceBase):

    @validate_user
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

    @validate_user
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

    @validate_user
    @exception_handler
    def on_get(self, req, resp):
        user = req.context['user']
        r = user.orgs_admin_of()
        lst = list(r)

        resp.media = {"result": lst, "message": "See result."}
        resp.status = falcon.HTTP_200
        return


class OrgsUserOf(ResourceBase):

    @validate_user
    @exception_handler
    def on_get(self, req, resp):
        user = req.context['user']
        r = user.orgs_user_of()
        lst = list(r)

        resp.media = {"result": lst, "message": "See result."}
        resp.status = falcon.HTTP_200
        return


class UserInfoSelf(ResourceBase):

    @validate_user
    @exception_handler
    def on_get(self, req, resp):
        user = req.context['user']

        resp.media = {"result": user.doc_no_pass,
                      "message": "See result."}
        resp.status = falcon.HTTP_200
        return
    

