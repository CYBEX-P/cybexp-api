"""falcon tests for api.views.query"""

import builtins
import json
import pdb
from pprint import pprint
import unittest

from falcon import testing
import gridfs
import mongomock
from mongomock.gridfs import enable_gridfs_integration
enable_gridfs_integration()

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
    builtins.u1 = User('user1@example.com', 'Abcd1234', 'User 1')
    builtins.o1 = Org('org1', u1, u1, 'Organization 1')
    builtins.token = o1.token
    builtins.headers = {'authorization': 'Bearer ' + token}    
    
def delete_test_data():
    del builtins.u1, builtins.o1, builtins.token, builtins.headers


def setUpModule():
    global _ID_B
    
    _backend = setUpBackend()
    _ID_B = _backend
    Instance.set_backend(_backend)
    api.configureIDBackend(_backend)

    file_entries, fs = get_mock_cahce_db()
    api.configureCacheDB(file_entries, fs)

    assert User._backend is Instance._backend
    assert SuperUser._backend is Instance._backend
    assert Org._backend is Instance._backend
    assert isinstance(Org._backend, (IdentityBackend, MockIdentityBackend))
    

def tearDownModule():
    tearDownBackend(_ID_B)


class BaseTestCase(testing.TestCase):
    def setUp(self):
        super(BaseTestCase, self).setUp()
        self.app = api.app


class PostRawTest(BaseTestCase):
    
    @classmethod
    def setUpClass(cls):
        assert _ID_B.find_one() is None
        make_test_data()
        e = {"key": "value"}
        j = json.dumps(e)
        builtins.files = {'file':  e}
        
        builtins.data = {
            'orgid': o1._hash,
            'name': 'UNR Cowrie Honeypot',
            'typetag': 'cowrie',
        
        }

    @classmethod
    def tearDownClass(cls):
        delete_test_data()
        del builtins.data
        _ID_B.drop()
        
    def test_01(self):
        res = self.simulate_post('/raw',
                                    json=data, headers=headers)
##        print(res.json)
##        org10 = Org._backend.find_org('org10', parse=True)
##        EQ = self.assertEqual
##        IN = self.assertIn
##        EQ(res.status_code, 201)
##        EQ(res.json['message'], 'Org created!')
##        EQ(res.json['result'], org10.doc)




if __name__ == '__main__':
    unittest.main()
