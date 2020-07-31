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

    def hash_to_user(self, usr_hash):
        raw_user = self.ident_backend.find_one({"_hash": usr_hash},{"_id":0})
        if raw_user:
            user = parse(raw_user, self.ident_backend)
            return user
        return None

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
        Usage
        -----
        @_extract_request_data()
        @_validate_token
        def some_func(self, req, resp):
            pass
        '''
        def wrapper(self, req, resp, *args, **kwargs):

            # req = kwargs["req"]
            # resp = kwargs["resp"]

            # try:
            #     request_data = {}
            #     request_data['req_timestamp'] = time.time()
            #     for part in req.media:
            #         request_data[part.name] = part.text

            # except falcon.errors.HTTPBadRequest as err:
            #       resp.media = {"message" : "Invalid input! " +
            #                     repr(err) + str(err)}
            #       resp.status = falcon.HTTP_400

            try:
                request_data = kwargs["request_data"]
                token = request_data["token"]
                # token = req.media.get('token')
                if self._is_token_revoked(token):
                    resp.media = {"message": "1: Invalid token"}
                    resp.status = falcon.HTTP_401
                    return

                payload = self.get_payload(token)
                if payload:
                    user = self.hash_to_user(payload["_hash"])

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

    def _extract_request_data(required_fields:list=[]):
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

            else: # user exists
                resp.media = {"message" : "User already exists"}
                resp.status = falcon.HTTP_409
                return
        except:
            traceback.print_exc()
            resp.media = {"message" : "Server Error"}
            resp.status = falcon.HTTP_500
            return

    @_validate_token
    def addOrg(self, req, resp, **kwargs):
        raise Exception("TODO; add org not implemented")
        pass



    # GOOD example, call extract then validate

    @_extract_request_data(required_fields=["email"])
    # @_extract_request_data()
    @_validate_token
    def test(self, req, resp, request_data, **kwargs):
        print("req data:", request_data)
        resp.media = {"message" : "it worked"}
        resp.status = falcon.HTTP_200
        return