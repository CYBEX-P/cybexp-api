"""falcon tests for api.views.raw"""

import builtins as bi
import json
import logging
import pdb
from pprint import pprint
import random
import unittest

from falcon import testing
import gridfs
import mongomock
from mongomock.gridfs import enable_gridfs_integration
enable_gridfs_integration()
from requests_toolbelt import MultipartEncoder

import tahoe
from tahoe import Instance
from tahoe.identity import SuperUser, User, Org
from tahoe.identity.backend import IdentityBackend, MockIdentityBackend
from tahoe.tests.identity.test_backend import setUpBackend, tearDownBackend

if __name__ != 'api.tests.test_views.test_raw':
    import sys, os
    J = os.path.join
    sys.path = ['..', J('..', '..'), J('..', '..', '..')] + sys.path
    del sys, os


import api
from views.crypto import encrypt_file

_LOGGER = logging.getLogger()

_ID_B = None
"""Identity Backend."""

def get_mock_cahce_db():
    dbname = 'a4061a42-62a9-4576-bc00-d0998a5135a6'
    collname = 'file_entries'
    
    client = mongomock.MongoClient()
    db = client.get_database(dbname)
    coll = db.get_collection(collname)
    fs = gridfs.GridFS(db)

    return coll, fs


def make_test_data():
    u1 = User('user1@example.com', 'Abcd1234', 'User 1')
    u2 = User('user2@example.com', 'Abcd1234', 'User 2')

    token = u1.token
    token2 = u2.token
    
    bi.o1 = Org('org1', u1, u1, 'Organization 1')

    bi.headers = {'authorization': 'Bearer ' + token}
    bi.headers2 = {'authorization': 'Bearer ' + token2}
    
    
def delete_test_data():
    del bi.o1, bi.headers, bi.headers2


def setUpModule():
    global _ID_B
    
    _backend = setUpBackend()
    _ID_B = _backend

    Instance.set_backend(_backend)
    api.configureIDBackend(_backend)

    bi.file_entries, bi.fs = get_mock_cahce_db()
    api.configureCacheDB(file_entries, fs)

    assert User._backend is Instance._backend
    assert SuperUser._backend is Instance._backend
    assert Org._backend is Instance._backend
    assert isinstance(Org._backend, (IdentityBackend, MockIdentityBackend))
    

def tearDownModule():
    tearDownBackend(_ID_B)

    del bi.file_entries, bi.fs


class BaseTestCase(testing.TestCase):
    def setUp(self):
        super(BaseTestCase, self).setUp()
        self.app = api.app


class PostQueryTest(BaseTestCase):

                
    @classmethod
    def setUpClass(cls):
        assert _ID_B.find_one() is None
        make_test_data()
        
    @classmethod
    def tearDownClass(cls):
        delete_test_data()
        _ID_B.drop()
        del bi.EQ, bi.post


    def test_00(self):
        bi.EQ = self.assertEqual
        bi.post = self.simulate_post

    def test_01_success(self):
        f = self.form()
        res = post('/raw', headers=headers, body=f.read(),
                   content_type=f.content_type)
        EQ(res.status_code, 201)
        EQ(res.json['message'], "File uploaded successfully!")
        EQ(file_entries.count_documents({}), 1)

        fe = file_entries.find_one({})
        EQ(fe['processed'], False)
        EQ(fe['name'], 'UNR Cowrie Honeypot')
        EQ(fe['typetag'], 'cowrie')
        EQ(fe['orgid'], o1._hash)
        EQ(fe['timezone'], 'US/Pacific')
        self.assertIsNotNone(fs.get(fe['fid']))
        
    def test_02_error_no_auth_header(self):
        _LOGGER.disabled = True                
        res = post('/raw')
        EQ(res.status_code, 401)
        EQ(res.json['message'], "Invalid/missing token in auth header!")
        _LOGGER.disabled = False

    def test_03_error_token_not_bearer(self):
        _LOGGER.disabled = True                
        res = post('/raw', headers={'authorization':'Invalid JWT token'})
        EQ(res.status_code, 401)
        EQ(res.json['message'], "Token must be of type Bearer!")
        _LOGGER.disabled = False

    def test_04_error_token_invalid(self):
        _LOGGER.disabled = True                
        res = post('/raw', headers={'authorization':'Bearer invalid'})
        EQ(res.status_code, 401)
        EQ(res.json['message'], "Invalid/missing token in auth header!")
        _LOGGER.disabled = False
               
    def test_05_error_user_not_admin(self):
        f = self.form()
        res = post('/raw', headers=headers2, body=f.read(),
                   content_type=f.content_type)
        EQ(res.status_code, 401)
        EQ(res.json['message'], "You are not an admin of this org!")

    def test_06_error_user_does_not_exist(self):
        _LOGGER.disabled = True                
        res = post('/raw', headers={'authorization':'Bearer ' + o1.token})
        EQ(res.status_code, 401)
        EQ(res.json['message'], "User does not exist!")
        _LOGGER.disabled = False

    def test_07_error_no_name(self):
        _LOGGER.disabled = True                
        f = self.form(remove_fields=('name'))
        res = post('/raw', headers=headers, body=f.read(),
                   content_type=f.content_type)
        EQ(res.status_code, 400)
        EQ(res.json['message'], "Invalid input: KeyError('name') 'name'!")
        _LOGGER.disabled = False

    def test_08_error_no_typetag(self):
        _LOGGER.disabled = True                
        f = self.form(remove_fields=('typetag'))
        res = post('/raw', headers=headers, body=f.read(),
                   content_type=f.content_type)
        EQ(res.status_code, 400)
        EQ(res.json['message'],
           "Invalid input: KeyError('typetag') 'typetag'!")
        _LOGGER.disabled = False

    def test_09_error_no_orgid(self):
        _LOGGER.disabled = True                
        f = self.form(remove_fields=('orgid'))
        res = post('/raw', headers=headers, body=f.read(),
                   content_type=f.content_type)
        EQ(res.status_code, 400)
        EQ(res.json['message'], "Invalid input: KeyError('orgid') 'orgid'!")
        _LOGGER.disabled = False

    def test_10_orgid_is_orgname(self):
        file_entries.drop()
        f = self.form(orgid=o1.orgname)
        res = post('/raw', headers=headers, body=f.read(),
                   content_type=f.content_type)
        EQ(res.status_code, 201)
        
        fe = file_entries.find_one({})
        EQ(fe['orgid'], o1._hash)

    def test_11_error_invalid_orgid(self):
        _LOGGER.disabled = True                
        f = self.form(orgid="invalid_orgid")
        res = post('/raw', headers=headers, body=f.read(),
                   content_type=f.content_type)
        EQ(res.status_code, 400)
        EQ(res.json['message'], "Invalid 'orgid'=invalid_orgid!")
        _LOGGER.disabled = False

    def test_12_no_timezone(self):
        file_entries.drop()
        f = self.form(remove_fields='timezone')
        res = post('/raw', headers=headers, body=f.read(),
                   content_type=f.content_type)
        EQ(res.status_code, 201)
        fe = file_entries.find_one({})
        EQ(fe['timezone'], 'UTC')

    def test_13_error_no_file(self):
        file_entries.drop()
        f = self.form(remove_fields='file')
        res = post('/raw', headers=headers, body=f.read(),
                   content_type=f.content_type)
        EQ(res.status_code, 400)
        EQ(res.json['message'], "Invalid or missing file!")
        _LOGGER.disabled = False
        

    






if __name__ == '__main__':
    unittest.main()
