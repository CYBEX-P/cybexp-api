"""falcon tests for api.identity.common"""

import builtins
import falcon
from falcon import testing
import logging
import pdb
import unittest

import tahoe

from tahoe.tests.identity.test_backend import setUpBackend, tearDownBackend

_LOGGER = logging.getLogger()


if __name__ != 'api.tests.identity.test_common':
    import sys, os
    sys.path = ['..', os.path.join('..', '..'),
                os.path.join('..', '..', '..')] + sys.path
    del sys, os


import api, resource


_ID_B = None
"""Identity Backend."""


def make_test_data():
    tahoe.identity.Identity._backend = _ID_B
    builtins.admin = tahoe.identity.User('admin@example.com')
    builtins.token = admin.token
    builtins.headers = {'authorization': 'Bearer ' + token}
    builtins.data = {
            'email': '1@b.c',
            'password': 'abc',
            'password2': 'abc',
            'name': 'test_user'
            }
    builtins.drf = {'f1':'v1', 'f2':'v2'}
       
    
def delete_test_data():
    del builtins.admin, builtins.token, builtins.headers


def setUpModule():
    global _ID_B
    
    _backend = setUpBackend()
    _ID_B = _backend
    api.configureIDBackend(_backend)
    

def tearDownModule():
    tearDownBackend(_ID_B)


class BaseTestCase(testing.TestCase):
    def setUp(self):
        super(BaseTestCase, self).setUp()
        self.app = api.app


class ResourceToTestExceptionHandler(resource.common.ResourceBase):
    """This is not a test case by itself."""
    
    @resource.common.exception_handler
    def on_get(self, req, resp):
        resp.media = {"message" : "Test successful!"}
        resp.status = falcon.HTTP_200
        return


class TestExceptionHandler(BaseTestCase):
    @classmethod
    def setUpClass(cls):
        assert _ID_B.find_one() is None
        api.app.add_route('/test/exception_handler',
                           ResourceToTestExceptionHandler())

    @classmethod
    def tearDownClass(cls):
        _ID_B.drop()
        
    def test1(self):
        result = self.simulate_get('/test/exception_handler')

        EQ = self.assertEqual
        EQ(result.status_code, 200)
        EQ(result.json['message'], 'Test successful!')


class ResourceToTestRequireFields(resource.common.ResourceBase):
    """This is not a test case."""
    
    @resource.common.require_fields()
    def on_get(self, req, resp):
        resp.media = {"message": "Success!"}
        resp.status = falcon.HTTP_200
        return

    @resource.common.require_fields(['f1', 'f2'])
    def on_post(self, req, resp):
        resp.media = req.context['media']
        resp.status = falcon.HTTP_200
        return
    

class TestRequireFields(BaseTestCase):
    @classmethod
    def setUpClass(cls):
        assert _ID_B.find_one() is None
        make_test_data()
        api.app.add_route('/test/require_fields',
                           ResourceToTestRequireFields())

    @classmethod
    def tearDownClass(cls):
        delete_test_data()
        _ID_B.drop()
        
    def test_on_get(self):        
        result = self.simulate_get('/test/require_fields',
                                   headers=headers)
        EQ = self.assertEqual
        EQ(result.status_code, 200)
        EQ(result.json['message'], 'Success!')

    def test_on_post(self):
        result = self.simulate_post('/test/require_fields',
                                   json=drf, headers=headers)
        EQ = self.assertEqual
        EQ(result.status_code, 200)
        EQ(result.json['f1'], 'v1')
        EQ(result.json['f2'], 'v2')        


class ResourceToTestValidateToken(resource.common.ResourceBase):
    """This is not a test case by itself."""
    
    @resource.common.validate_user
    def on_get(self, req, resp):
        resp.media = req.context['user'].doc
        resp.status = falcon.HTTP_200
        return

    @resource.common.validate_user
    def on_post(self, req, resp):
        resp.media = req.context['user'].doc
        resp.status = falcon.HTTP_200
        return
    

class TestValidateToken(BaseTestCase):
    @classmethod
    def setUpClass(cls):
        assert _ID_B.find_one() is None
        make_test_data()
        api.app.add_route('/test/validate_token',
                           ResourceToTestValidateToken())

    @classmethod
    def tearDownClass(cls):
        delete_test_data()
        _ID_B.drop()
        
    def test_on_get(self):        
        result = self.simulate_get('/test/validate_token',
                                   headers=headers)
        EQ = self.assertEqual
        EQ(result.status_code, 200)
        EQ(result.json['itype'], 'object')
        EQ(result.json['sub_type'], 'cybexp_user')
        EQ(result.json['_hash'], admin._hash)

    def test_on_post(self):        
        result = self.simulate_post('/test/validate_token',
                                   json=data, headers=headers)
        EQ = self.assertEqual
        EQ(result.status_code, 200)
        EQ(result.json['itype'], 'object')
        EQ(result.json['sub_type'], 'cybexp_user')
        EQ(result.json['_hash'], admin._hash)

    def test_err_missing_token(self):
        _LOGGER.disabled = True
        
        result = self.simulate_get('/test/validate_token')
        EQ = self.assertEqual
        EQ(result.status_code, 401)
        EQ(result.json['message'], 'Invalid/missing token in auth header!')

        _LOGGER.disabled = False

    def test_err_bearer(self):
        _LOGGER.disabled = True
        
        wr_headers = {'authorization': 'Not_bearer ' + token}
        result = self.simulate_get('/test/validate_token', headers=wr_headers)
        EQ = self.assertEqual
        EQ(result.status_code, 401)
        EQ(result.json['message'], 'Token must be of type Bearer!')

        _LOGGER.disabled = False

    def test_err_invalid_token(self):
        _LOGGER.disabled = True
        
        wr_headers = {'authorization': 'Bearer ' + 'invalid_token'}
        result = self.simulate_get('/test/validate_token', headers=wr_headers)
        EQ = self.assertEqual
        EQ(result.status_code, 401)
        EQ(result.json['message'], 'Invalid/missing token in auth header!')

        _LOGGER.disabled = False

    


        

if __name__ == '__main__':
    unittest.main()
