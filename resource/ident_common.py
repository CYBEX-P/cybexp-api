import falcon
import time
import logging
import pymongo
import traceback
import sys

# import loadconfig
# from . import crypto

sys.path.insert(1, '/home/nacho/Projects/tahoe0.7-dev/')


import tahoe
from tahoe import NoBackend, Attribute, parse
from tahoe.identity import IdentityBackend, Identity, User, Org




token_checker =Identity(sub_type="_invalid_type",
                        data=[Attribute("_invalid_att",False, _backend=NoBackend())],
                        _backend=NoBackend()
                      )
def get_payload(token, token_checker=token_checker) :
    """
    token_checker is an Identity object that has no backend
    """
    try:
        decoded = token_checker.getpayload(token)
        return decoded
    except:
        return None


def hash_to_object(idnt_bnd, obj_hash):
    raw_obj = idnt_bnd.find_one({"_hash": obj_hash},{"_id":0})
    if raw_obj:
        obj = parse(raw_obj, idnt_bnd)
        return obj
    return None

def hash_to_user(idnt_bnd,usr_hash):
    return hash_to_object(idnt_bnd, usr_hash)

def hash_to_org(idnt_bnd,org_hash):
    return hash_to_object(idnt_bnd,org_hash)

def is_token_revoked(ident_backend,token):
    # raise Exception("todo check token revoked")
    print("TODO: check token in revocation list")
    # TODO
    return False

def org_name_to_hash(idnt_bnd, name):
    filt = {"_hash":1,"_id":0}
    query = {"itype":"attribute","sub_type" : "orgname", "data":name}
    name_record = idnt_bnd.find_one(query, filt)
    if name_record:
        name_hash = name_record["_hash"]
        query = {"itype":"object","sub_type" : "cybexp_org", "_ref":name_hash}
        org_record = idnt_bnd.find_one(query, filt)
        if org_record:
            return org_record["_hash"]
    return None

def is_user_in_org(idnt_bnd, org_name, user_hash):
    filt = {"_hash":1,"_id":0}
    org_hash = org_name_to_hash(idnt_bnd, name)
    if org_hash:
        query = {"_hash":org_hash, "_usr_ref":user_hash}
        if idnt_bnd.find_one(query, filt):
            return True
        else:
            False
    else:
        return False

def is_user_admin_of_org(idnt_bnd, org_name, user_hash):
    filt = {"_hash":1,"_id":0}
    org_hash = org_name_to_hash(idnt_bnd, name)
    if org_hash:
        query = {"_hash":org_hash, "_adm_ref":user_hash}
        if idnt_bnd.find_one(query, filt):
            return True
        else:
            False
    else:
        return False


def early_return(resp):
    """
    to be used by decorators before decorating/calling a function. 
    will return true if it determines that a previous decorator wanted to return.
    will return false otherwise, tehrefore ok to decorate and not return yet.
    """
    try:
        if "message" in resp.media and resp.status >= falcon.HTTP_300:
            return True
        else:
            return False
    except (KeyError,TypeError):
        return False
    return True


def validate_token(func):
    '''Check validity of the token, if it fails it returns 401. 
        named argument `request_data` must be passed in to original function
        or @extract_request_data() must be called before hand.
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
    # print("args", main_args)
    # print("kw_args", main_kwargs)
    # def decorator_wrapper(func):
        # print("func",type(func))
    def wrapper(self, req, resp, *args, **kwargs):

        try:
            if early_return(resp):
                return
            request_data = kwargs["request_data"]
            # print(request_data)
            token = request_data["token"]
            # token = req.media.get('token')
            # print(self)
            if is_token_revoked(self.ident_backend, token):
                resp.media = {"message": "Invalid token"}
                resp.status = falcon.HTTP_401
                return

            payload = get_payload(token) # if valid therefore there exists valid user
            if payload:
                user = hash_to_user(self.ident_backend, payload["_hash"])

                if user == None:
                    resp.media = {"message": "User does not exist"}
                    resp.status = falcon.HTTP_409
                    return

                kwargs["user_object"] = user

                r = func(self, req, resp, *args,**kwargs)
                return r
            else:
                resp.media = {"message": "Invalid token"}
                resp.status = falcon.HTTP_401
                return
        except:
            traceback.print_exc()
            resp.media = {"message": "3: Invalid token"}
            resp.status = falcon.HTTP_401
            return

    return wrapper
    # return decorator_wrapper

def get_org_object(func):
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
                org_name = request_data["orgname"]
                # org_hash = request_data["org_hash"]
            except:
                # traceback.print_exc()
                resp.media = {"message": "Missing orgname"}
                resp.status = falcon.HTTP_400
                return
            org_hash = org_name_to_hash(self.ident_backend,org_name)
            # print("org hash", org_hash)
            org = hash_to_object(self.ident_backend ,org_hash)
            # print(org)
            print(type(org))
            # org = hash_to_org(self.ident_backend, org_hash)
            if org == None:
                    resp.media = {"message": "Forbidden"}
                    resp.status = falcon.HTTP_403
                    return

            kwargs["org_object"] = org

            r = func(self, req, resp, *args,**kwargs)
            return r
            
        except:
            traceback.print_exc()
            resp.media = {"message": "Server Error!"}
            resp.status = falcon.HTTP_500
            return

    return wrapper

def extract_request_data(*args_main, **kwrgs_main):
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
    
    # fix how external objects call this, non TokenManager() objects
    # print("args test:", args_main)
    # print("kwargs test", kwrgs_main)
    required_fields = kwrgs_main.pop("required_fields", [])
    # print("req", required_fields)
    

    def decorator_wrapper(func):
        def wrapper(self, req, resp, *args, **kwargs):
            # print("w:", req, resp)
            # req = kwargs["req"]
            # resp = kwargs["resp"]

            try:
                # request_data = {}
                # token = req.media.get_param('token')

                # print(req.media)
                # for part in req.media:
                #     print("hit")
                #     request_data[part.name] = part.txt
                
                request_data = dict(req.media)
                request_data['req_timestamp'] = time.time()

                # print("full req data:",request_data)

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
                  resp.media = {"message" : "Invalid input!"} #+
                                # repr(err) + str(err)}
                  resp.status = falcon.HTTP_400
                  return

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


def exception_handler(func):
    def wrapper(self, req, resp,*args, **kwargs):
        try:
            return func(self, req, resp,*args, **kwargs)
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
    return wrapper




def required_groups_any(*args_main, **kwrgs_main):
    org_list = kwrgs_main.pop("required_groups_any", [])
   

    def decorator_wrapper(func):
        def wrapper(self, req, resp,*args, **kwargs):
            # print("w:", req, resp)
            # req = kwargs["req"]
            # resp = kwargs["resp"]

            if early_return(resp):
                return
            try:
                user_object = kwargs.get("user_object", None)
                if user_object == None:
                    raise Exception("call the validate_token decorator before this one.")
                for org_name in org_list:
                    if is_user_in_org(self.ident_backend, org_name, user_object._hash):
                        r = func(self, req, resp, *args,**kwargs)
                        return r
                    else:
                        resp.media = {"message": "Forbidden"}
                        resp.status = falcon.HTTP_404
                        # resp.status = falcon.HTTP_403
                        return

            except falcon.errors.HTTPBadRequest as err:
                  resp.media = {"message" : "Invalid input! " +
                                repr(err) + str(err)}
                  resp.status = falcon.HTTP_400



        return wrapper
    return decorator_wrapper


# todo
# redo documentation
# add @require_group("admin")
# docs; decorators must have self.ident_backend

if __name__ == '__main__':
    ident_mongo_url="mongodb://localhost"
    idnt_bnd = IdentityBackend(mongo_url=ident_mongo_url, create=False)
    Identity._backend = idnt_bnd 