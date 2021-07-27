"""Common resources and decorators."""

import falcon
import logging
import pdb
import pymongo
import time

import tahoe
from tahoe.identity import Identity


class ResourceBase(object):
    _backend = tahoe.backend.NoBackend()
    """
    Identity backend; will be initialized by api.py and used by all
    other resource classes when they inherit the ResourceBase.
    """


def configureIDBackend(_backend, secret="secret"):
    """
    `api.py` will call this function to setup identity backend.

    This file stores the identity backend information in two variables
    - `Identity._backend` and `ResourceBase._backend`. Both this
    variables need to be set for the rest of the code to work. However,
    identity backend is not known at the begining. So `api.py` does
    first initilizes the IdentityBackend object then sets these two
    variables using this function.

    Parameters
    ----------
    _backend : tahoe.identity.backend.IdentityBackend
        The `IdentityBackend` object.
    """

    ResourceBase._backend = _backend
    Identity._backend = _backend
    Identity.secret = secret


def _early_return(resp):
    """
    To be used by decorators before decorating/calling a function.

    If `True` the decorator should return immediately so that
    error message from previous decorator is not overwritten.

    Returns
    -------
    True
        If the previous decorator wanted to return (a message).
    False
        Otherwise

    Examples
    --------
    Example usage::
    
        def some_decorator(func):
            def wrapper(self, req, resp, *args, **kwargs):
                if _early_return(resp):
                    return
                '''continue wrapper...'''
    """
    
    try:
        if "message" in resp.media and resp.status >= falcon.HTTP_300:  
            return True
        else:
            return False
    except (KeyError, TypeError):
        return False
    return True



def exception_handler(func):
    """Catches and handles all exceptions."""
    
    def wrapper(self, req, resp, *args, **kwargs):
        if _early_return(resp):
            return
        
        try:
            return func(self, req, resp, *args, **kwargs)
            
        except (KeyError, falcon.errors.HTTPBadRequest) as err:
              resp.media = {"message" : "Invalid input: " +
                            repr(err) + ' ' + str(err) + '!'}
              resp.status = falcon.HTTP_400
              return
          
        except pymongo.errors.ServerSelectionTimeoutError:
            logging.exception("Database down")
            resp.media = {"message" : "Database down"}
            resp.status = falcon.HTTP_500
            return

        except (KeyboardInterrupt, SystemExit):
            raise
          
        except:
            logging.exception("Exception", exc_info=True)
            resp.media = {"message" : "500 Server Error"}
            resp.status = falcon.HTTP_500
            return
    return wrapper


def require_fields(fields=[]):
    """
    Examples
    --------
    Example usage::

        @require_fields()  # notice the parenthesis
        @exception_handler # exception_handler must come last
        def some_func:
            return

        @require_fields([f1, f2])  # argument is list of str
        def some_func:
            return
    """
    
    def inner(func):
        def wrapper(self, req, resp, *args, **kwargs):
            if _early_return(resp):
                return

            try:
                req_media = req.media

                missing_fields = []
                for f in fields:
                    if f not in req_media:
                        missing_fields.append(f)

                if missing_fields:   
                    resp.media = {"message" :
                        "Missing the following fields: {}".format(missing_fields)}
                    resp.status = falcon.HTTP_400
                    return
            except:
                logging.exception("Error in require_fields", exc_info=True)
                resp.media = {"message": "Invalid input data!"}
                resp.status = falcon.HTTP_400
                return

            req.context['media'] = req_media
            return func(self, req, resp, *args,**kwargs)

        return wrapper
    return inner


def validate_org(func):
    """
    Validates the JWT token and gets tahoe Org object.

    Returns
    -------
    401
        If token is invalid.
    tahoe.identity.org.Org
        The Org object associated with the JWT token.
        
    Examples
    --------
    Example usage::
    
        @validate_org
        @exception_handler
        def on_post(self, req, resp):
            user = req.context['user']
    """
    
    def wrapper(self, req, resp, *args, **kwargs):
        if _early_return(resp):
                return
            
        try:
            auth_list = req.auth.split(" ", 1)
            token_type = auth_list[0]
            token = auth_list[1].strip()

            if token_type != "Bearer":
                resp.media = {"message": "Token must be of type Bearer!"}
                resp.status = falcon.HTTP_400
                return
            
            if Identity.is_token_revoked(token):
                resp.media = {"message": "JWT token is revoked."}
                resp.status = falcon.HTTP_401
                return
            
            payload = Identity.get_payload(token)
            org = Identity._backend.find_org(_hash=payload["_hash"], parse=True)

            if org is None:
                resp.media = {"message": "Org does not exist!"}
                resp.status = falcon.HTTP_409
                return

            req.context['org'] = org

        except (KeyboardInterrupt, SystemExit):
            raise
        
        except pymongo.errors.ServerSelectionTimeoutError:
            logging.exception("Cache DB - Identity Backend down!", exc_info=True)
            resp.media = {"message": "Authentication database down!"}
            resp.status = falcon.HTTP_500
            return
            
        except:
            logging.exception("Error in validate_org", exc_info=True)
            resp.media = {"message": "Invalid/missing token in auth header!"}
            resp.status = falcon.HTTP_401
            return

        return func(self, req, resp, *args,**kwargs)

    return wrapper


def validate_user(func):
    """
    Validates the JWT token and gets tahoe User object.

    Returns
    -------
    401
        If token is invalid.
    tahoe.identity.user.User
        The User object associated with the JWT token.
        
    Examples
    --------
    Example usage::
    
        @validate_user
        @exception_handler
        def on_post(self, req, resp):
            user = req.context['user']
    """
    
    def wrapper(self, req, resp, *args, **kwargs):
        if _early_return(resp):
                return
            
        try:
            auth_list = req.auth.split(" ", 1)
            token_type = auth_list[0]
            token = auth_list[1].strip()

            if token_type != "Bearer":
                resp.media = {"message": "Token must be of type Bearer!"}
                resp.status = falcon.HTTP_401
                return
            
            if Identity.is_token_revoked(token):
                resp.media = {"message": "JWT token is revoked."}
                resp.status = falcon.HTTP_401
                return
            
            payload = Identity.get_payload(token)
            user = Identity._backend.find_user(_hash=payload["_hash"], parse=True)

            if user is None:
                resp.media = {"message": "User does not exist!"}
                resp.status = falcon.HTTP_401
                return

            req.context['user'] = user

        except (KeyboardInterrupt, SystemExit):
            raise
        
        except pymongo.errors.ServerSelectionTimeoutError:
            logging.exception("Cache DB - Identity Backend down!", exc_info=True)
            resp.media = {"message": "Authentication database down!"}
            resp.status = falcon.HTTP_500
            return
            
        except:
            logging.exception("Error in validate_user", exc_info=True)
            resp.media = {"message": "Invalid/missing token in auth header!"}
            resp.status = falcon.HTTP_401
            return

        return func(self, req, resp, *args,**kwargs)

    return wrapper





