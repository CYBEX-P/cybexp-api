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
from tahoe.identity import IdentityBackend, Identity, User, Org

class TokenManager(object):

    def __init__(self, ident_mongo_url="mongodb://localhost"):
        self.token_checker = Identity(
                                    sub_type="_invalid_type",
                                    data=[Attribute("_invalid_att",False, _backend=NoBackend())],
                                    _backend=NoBackend()
                                )

        self.ident_backend = IdentityBackend(mongo_url=ident_mongo_url, create=False)
        Identity._backend = self.ident_backend # todo BUG; if there are multiple of TOkenManager, this will not work correclty


    def get_payload(self, token):
        try:
            decoded = self.token_checker.getpayload(token)
            return decoded
        except:
            return None


    def hash_to_object(self, obj_hash):
        raw_obj = self.ident_backend.find_one({"_hash": obj_hash},{"_id":0})
        if raw_obj:
            obj = parse(raw_obj, self.ident_backend)
            return obj
        return None

    def hash_to_user(self, usr_hash):
        return self.hash_to_object(user_hash)

    def hash_to_org(self, org_hash):
        return self.hash_to_object(user_hash)

    def _is_token_revoked(self,token):
        # raise Exception("todo check token revoked")
        print("TODO: check token in revocation list")
        # TODO
        return False

    def _validate_token(func):
        '''Check validity of the token, if it fails it returns 401. 
            named argument `request_data` must be passed in to original function
            or @_extract_request_data() must be called before hand.
            this decorator will get the token from request_data["token"].
            this decorator will place the user's tahoe object under the names argument `user_object`.
        Usage
        -----
        @_extract_request_data()
        @_validate_token
        def some_func(self, req, resp, **kwargs):
            request_data = kwargs["request_data"]
            user_object = kwargs["user_object"]
        '''
        def wrapper(self, req, resp, *args, **kwargs):

            try:
                request_data = kwargs["request_data"]
                token = request_data["token"]
                # token = req.media.get('token')
                if self._is_token_revoked(token):
                    resp.media = {"message": "1: Invalid token"}
                    resp.status = falcon.HTTP_401
                    return

                payload = self.get_payload(token) # if valid therefore there exists valid user
                if payload:
                    user = self.hash_to_user(payload["_hash"])

                    if user == None:
                        resp.media = {"message": "User does not exist"}
                        resp.status = falcon.HTTP_409
                        return

                    kwargs["user_object"] = user

                    r = func(self, req, resp, *args,**kwargs)
                    return r
                else:
                    resp.media = {"message": "2: Invalid token"}
                    resp.status = falcon.HTTP_401
                    return
            except:
                # traceback.print_exc()
                resp.media = {"message": "3: Invalid token"}
                resp.status = falcon.HTTP_401
                return

        return wrapper

    def _get_org_object(func):
        '''checks if key `org_hash` is in the names argument `request_data`. If it fails it returns 400. 
            named argument `request_data` must be passed in to original function
            or @_extract_request_data() must be called before hand.
            this decorator will get the `org_hash` from request_data["org_hash"].
            this decorator will place the orgs tahoe object under the names argument `org_object`.
        Usage
        -----
        @_extract_request_data()
        @_get_org_object
        def some_func(self, req, resp, **kwargs):
            request_data = kwargs["request_data"]
            org_object = kwargs["org_object"]
            pass
        '''
        def wrapper(self, req, resp, *args, **kwargs):

            try:
                try:
                    request_data = kwargs["request_data"]
                    org_hash = request_data["org_hash"]
                except:
                    # traceback.print_exc()
                    resp.media = {"message": "Missind org_hash"}
                    resp.status = falcon.HTTP_400
                    return

                org = self.hash_to_org(org_hash)
                if org == None:
                        resp.media = {"message": "Org does not exist"}
                        resp.status = falcon.HTTP_409
                        return

                kwargs["org_object"] = org

                r = func(self, req, resp, *args,**kwargs)
                return r
                
            except:
                # traceback.print_exc()
                resp.media = {"message": "Server Error!"}
                resp.status = falcon.HTTP_500
                return

        return wrapper

    def _extract_request_data(*args_main, **kwrgs_main):
        '''This decorator grab the data from the falcon request object and pass it
            into the original function as a named argument named `request_data`.
            This decorator can also enforce fields in the request, add them to `required _fields` decorator argument.
            For usage see note below, else this will missbehave or throw error.
            If no enforcement is given, `request_data` will only contain `req_timestamp`
        Note
        ----
        This decorator must be called `@_extract_request_data()`, if only wanting to extract only and not enforce ( use the parenthesis). 
        Or `@_extract_request_data(required_fields=["email", "password"])` if wanting to enforce fields.
        '''
        
        print("args test:", args_main)
        print("kwargs test", kwrgs_main)
        required_fields = kwrgs_main.pop("required_fields", [])
        print("req", required_fields)
        

        def decorator_wrapper(func):
            def wrapper(self, req, resp, *args, **kwargs):
                print("w:", req, resp)
                # req = kwargs["req"]
                # resp = kwargs["resp"]

                try:
                    request_data = {}
                    request_data['req_timestamp'] = time.time()
                    # token = req.media.get_param('token')

                    print(req.media)
                    for part in req.media:
                        print("hit")
                        request_data[part.name] = part.text
                    print("full req data:",request_data)

                    if len(required_fields) > 0:
                        missing_fields = list()
                        for field in required_fields:
                            if field not in request_data.keys():
                                missing_fields.append(field)
                        if len(missing_fields) > 0:   
                            resp.media = {"message" : "Missing the following fields: {}".format(missing_fields)}
                            resp.status = falcon.HTTP_400
                            return

                except falcon.errors.HTTPBadRequest as err:
                      resp.media = {"message" : "Invalid input! " +
                                    repr(err) + str(err)}
                      resp.status = falcon.HTTP_400

                try:
                    kwargs["request_data"] = request_data
                    r = func(self, req, resp, *args,**kwargs)
                    return r
            
                except:
                    traceback.print_exc()
                    resp.media = {"message": "Invalid request"}
                    resp.status = falcon.HTTP_400
                    # resp.media = {"message" : "Server Error!"}
                    # resp.status = falcon.HTTP_500
                    return

            return wrapper
        return decorator_wrapper

        
    def on_post(self, req, resp, var1,var2=None, **kwargs):
        # default return
        # resp.media = {"message" : "404 Not Found"} # more authentic without body
        resp.status = falcon.HTTP_404

        try:
            path = req.path
            print("Path:", path)
            print("var1:",var1)
            print("var2:",var2)

            if var1 == "register":
                print("registering")
                return self.registerUser(req, resp)

            elif var1 == "login":
                print("logging in")
                # return self.login(req, resp)

            elif var1 == "token-test":
                print("checking token")
                # return self.token_test(req, resp)

            elif var1 == "logout":
                return self.logout(req, resp)

            elif var1 == "create" and var2 != None:
                print("creating ", "")
                if var2 == "user":
                    print("user")
                    return self.registerUser(req, resp)

                elif var2 == "org":
                    print("org")
                    # return self.addOrg(req, resp)


            elif var1 == "debug" and var2 != None:
                print("debug ", "")
                if var2 == "test":
                    print("running test endpoint")
                    return self.test(req, resp)

            else:
                resp.media = {"message" : "404 Not Found"}
                resp.status = falcon.HTTP_404
                return

          
        except falcon.errors.HTTPBadRequest as err:
              resp.media = {"message" : "Invalid input! " +
                            repr(err) + str(err)}
              resp.status = falcon.HTTP_400
              return
          
        except pymongo.errors.ServerSelectionTimeoutError:
            logging.exception("Backend down")
            resp.media = {"message" : "backend down"}
            resp.status = falcon.HTTP_500
            return

        except (KeyboardInterrupt, SystemExit):
            raise
          
        except:
            logging.exception("[API] TokenManager", exc_info=True)
            resp.media = {"message" : "Server Error!"}
            resp.status = falcon.HTTP_500
            return


    @_validate_token
    def token_test(self, req, resp, user_object, **kwargs):
        try:
            tok = user_object.token
            resp.media = {"message" : "Token valid", "token":tok}
            resp.status = falcon.HTTP_200
            # TODO return token in header
            return
        except:
            resp.media = {"message" : "401 Unauthorized"}
            resp.status = falcon.HTTP_401
            return

    @_extract_request_data(required_fields=["email", "password"])
    def login(self, req, resp, request_data, **kwargs):
        # required_fields = ["email", "password"]
        # missing_fields = list()
        # for field in required_fields:
        #     if field not in request_data.keys():
        #         missing_fields.append(field)
        # if len(missing_fields) > 0:   
        #     resp.media = {"message" : "Missing the following fields: {}".format(missing_fields)}
        #     resp.status = falcon.HTTP_400
        #     return

        if self.ident_backend.user_exists(request_data["email"]):
            user_hash = User(request_data["email"], _backend=NoBackend())._hash
            user = self.hash_to_user(user_hash)
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

    @_validate_token
    def logout(self, req, resp, **kwargs):
        # revoke key
        raise Exception("TODO; logout not implemented")
        pass

    @_extract_request_data(required_fields=["email", "password","password2","name"])
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
            traceback.print_exc()
            resp.media = {"message" : "Server Error"}
            resp.status = falcon.HTTP_500
            return


    @_extract_request_data(required_fields=["orgname", "user","admin","name"])
    @_validate_token
    def addOrg(self, req, resp, request_data, user_object, **kwargs):
        raise Exception("TODO; add org not implemented")
        
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


    # @_extract_request_data(required_fields=["orgname", "acl"])
    # @_validate_token
    # @_get_org_object
    # def change_org_acl(self, req, resp, request_data, user_object, org_object, **kwargs):

    #     try:
    #         org_object.set_acl()
    #     except TypError:
    #         resp.media = {"message" : "ACL must be a list of user hashses"}
    #         resp.status = falcon.HTTP_400
    #         return

    #     #if admin for org; do it


    # @_extract_request_data()
    # @_validate_token
    # def orgs_i_belong(self, req, resp, **kwargs):
    #     pass

    # @_extract_request_data()
    # @_validate_token
    # def orgs_i_admin(self, req, resp, **kwargs):
    #     pass



    # GOOD example, call extract then validate

    @_extract_request_data(required_fields=["email"])
    # @_extract_request_data()
    @_validate_token
    def test(self, req, resp, request_data, **kwargs):
        print("req data:", request_data)
        resp.media = {"message" : "it worked"}
        resp.status = falcon.HTTP_200
        return