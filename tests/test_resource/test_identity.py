"""falcon tests for api.identity.identity"""

import builtins
from falcon import testing
import pdb
from pprint import pprint
import unittest

import tahoe
from tahoe import Instance
from tahoe.identity import SuperUser, User, Org
from tahoe.identity.backend import IdentityBackend, MockIdentityBackend
from tahoe.tests.identity.test_backend import setUpBackend, tearDownBackend

if __name__ != 'api.tests.ttest_resource.test_identity':
    import sys, os
    J = os.path.join
    sys.path = ['..', J('..', '..'), J('..', '..', '..')] + sys.path
    del sys, os


import api


_ID_B = None
"""Identity Backend."""


def make_test_data():
    tahoe.identity.Identity._backend = _ID_B
    builtins.admin = SuperUser('admin@example.com')
    builtins.token = admin.token
    builtins.headers = {'authorization': 'Bearer ' + token}

    builtins.u1 = User('user1@example.com', 'Abcd1234', 'User 1')
    builtins.u2 = User('user2@example.com', 'Abcd1234', 'User 2')
    builtins.u3 = User('user3@example.com', 'Abcd1234', 'User 3')

    builtins.o1 = Org('org1', u1, u1, 'Organization 1')
    builtins.o2 = Org('org2', [u1,u2], u2, 'Organization 2')
    builtins.o3 = Org('org3', [u2], u2, 'Organization 3')

    builtins.tu1 = u1.token
    builtins.tu2 = u2.token
    builtins.tu3 = u3.token
    
    builtins.hu1 = {'authorization': 'Bearer ' + tu1}
    builtins.hu2 = {'authorization': 'Bearer ' + tu2}
    builtins.hu3 = {'authorization': 'Bearer ' + tu3}

    
    
def delete_test_data():
    del builtins.admin, builtins.token, builtins.headers, builtins.u1,
    builtins.u2, builtins.u3, builtins.o1, builtins.o2, builtins.o3,
    builtins.tu1, builtins.tu2, builtins.tu3, builtins.hu1, builtins.hu2,
    builtins.hu3        


def setUpModule():
    global _ID_B
    
    _backend = setUpBackend()
    _ID_B = _backend
    Instance.set_backend(_backend)
    api.configureIDBackend(_backend)

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

    def assertUserIsAdmin(self, user, org):
        IN = self.assertIn
        INN = self.assertIsNotNone
        
        orgd = org._backend.find_one({'_hash': org._hash})

        org_email = []
        for a in org.data['admin'][0]['cybexp_user']:
            org_email.append(a['email_addr'][0])
        orgd_email =  []
        for a in orgd['data']['admin'][0]['cybexp_user']:
            orgd_email.append(a['email_addr'][0])

        IN(user._hash, org._cref)
        IN(user._hash, org._ref)
        IN(user._hash, org._usr_ref)
        IN(user._hash, org._adm_ref)
        IN(user._hash, org._acl)
        IN(user.email, org_email)

        INN(orgd)
        IN(user._hash, orgd['_cref'])
        IN(user._hash, orgd['_ref'])
        IN(user._hash, orgd['_usr_ref'])
        IN(user._hash, orgd['_adm_ref'])
        IN(user._hash, orgd['_acl'])
        IN(user.email, orgd_email)

    def assertUserIsInOrg(self, user, org):
        IN = self.assertIn
        INN = self.assertIsNotNone
        
        orgd = org._backend.find_one({'_hash': org._hash})

        org_email = [u['email_addr'][0] for u in org.data['cybexp_user']]
        orgd_email = [u['email_addr'][0] for u in orgd['data']['cybexp_user']]
        
        IN(user._hash, org._cref)
        IN(user._hash, org._ref)
        IN(user._hash, org._usr_ref)
        IN(user._hash, org._acl)
        IN(user.email, org_email)

        INN(orgd)
        IN(user._hash, orgd['_cref'])
        IN(user._hash, orgd['_ref'])
        IN(user._hash, orgd['_usr_ref'])
        IN(user._hash, orgd['_acl'])
        IN(user.email, orgd_email)

    def assertUserIsNotAdmin(self, user, org):
        NIN = self.assertNotIn
        INN = self.assertIsNotNone
        
        orgd = org._backend.find_one({'_hash': org._hash})

        org_email = []
        for a in org.data['admin'][0]['cybexp_user']:
            org_email.append(a['email_addr'][0])
        orgd_email =  []
        for a in orgd['data']['admin'][0]['cybexp_user']:
            orgd_email.append(a['email_addr'][0])
        NIN(user._hash, org._adm_ref)
        NIN(user.email, org_email)
        INN(orgd)
        NIN(user._hash, orgd['_adm_ref'])
        NIN(user.email, orgd_email)

    def assertUserIsNotInOrg(self, user, org):
        NIN = self.assertNotIn
        INN = self.assertIsNotNone
        
        orgd = org._backend.find_one({'_hash': org._hash})

        org_email = [u['email_addr'][0] for u in org.data['cybexp_user']]
        orgd_email = [u['email_addr'][0] for u in orgd['data']['cybexp_user']]
        
        NIN(user._hash, org._cref)
        NIN(user._hash, org._ref)
        NIN(user._hash, org._usr_ref)
        NIN(user._hash, org._acl)
        NIN(user.email, org_email)

        INN(orgd)
        NIN(user._hash, orgd['_cref'])
        NIN(user._hash, orgd['_ref'])
        NIN(user._hash, orgd['_usr_ref'])
        NIN(user._hash, orgd['_acl'])
        NIN(user.email, orgd_email)

    def assertUserOnlyInAcl(self, user, org):
        IN = self.assertIn
        NIN = self.assertNotIn
        INN = self.assertIsNotNone
        
        orgd = org._backend.find_one({'_hash': org._hash})

        org_email = [u['email_addr'][0] for u in org.data['cybexp_user']]
        orgd_email = [u['email_addr'][0] for u in orgd['data']['cybexp_user']]
        
        NIN(user._hash, org._cref)
        NIN(user._hash, org._ref)
        NIN(user._hash, org._usr_ref)
        IN(user._hash, org._acl)
        NIN(user.email, org_email)

        INN(orgd)
        NIN(user._hash, orgd['_cref'])
        NIN(user._hash, orgd['_ref'])
        NIN(user._hash, orgd['_usr_ref'])
        IN(user._hash, orgd['_acl'])
        NIN(user.email, orgd_email)


class CreateOrgTest(BaseTestCase):
    
    @classmethod
    def setUpClass(cls):
        assert _ID_B.find_one() is None
        make_test_data()
        builtins.data = {
                'orgname': 'org10',
                'user': [u1._hash, u2._hash],
                'admin': [u1._hash, u2._hash],
                'name': 'Org 10'
            }

    @classmethod
    def tearDownClass(cls):
        delete_test_data()
        del builtins.data
        _ID_B.drop()
        
    def test_1_create_org(self):
        res = self.simulate_post('/create/org',
                                    json=data, headers=headers)
        org10 = Org._backend.find_org('org10', parse=True)
        EQ = self.assertEqual
        IN = self.assertIn
        EQ(res.status_code, 201)
        EQ(res.json['message'], 'Org created!')
        EQ(res.json['result'], org10.doc)

    def test_2_org_exists_error(self):
        result = self.simulate_post('/create/org',
                                    json=data, headers=headers)
        EQ = self.assertEqual
        IN = self.assertIn
        EQ(result.status_code, 400)
        EQ(result.json['message'], "Orgname = " \
           f"{data['orgname']} already exists!")

    def test_3_unauthorized_attempt(self):
        result = self.simulate_post('/create/org',
                                    json=data, headers=hu1)
        EQ = self.assertEqual
        IN = self.assertIn
        EQ(result.status_code, 401)
        EQ(result.json['message'], "Only CYBEX-P admin can create org!")



class CreateUserTest(BaseTestCase):
    
    @classmethod
    def setUpClass(cls):
        assert _ID_B.find_one() is None
        make_test_data()
        builtins.data = {
                'email': '1@b.c',
                'password': 'abc',
                'password2': 'abc',
                'name': 'test_user'
            }
        

    @classmethod
    def tearDownClass(cls):
        delete_test_data()
        del builtins.data
        _ID_B.drop()
        
    def test_1_create_user(self):
        result = self.simulate_post('/create/user',
                                    json=data, headers=headers)
        utemp = User._backend.find_user('1@b.c', parse=True)
        EQ = self.assertEqual
        IN = self.assertIn
        EQ(result.status_code, 201)
        EQ(result.json['message'], 'User created!')
        EQ(result.json['result'], utemp.doc_no_pass)
        IN('token', result.json)

    def test_2_user_exists_error(self):
        result = self.simulate_post('/create/user',
                                    json=data, headers=headers)
        EQ = self.assertEqual
        IN = self.assertIn
        EQ(result.status_code, 400)
        EQ(result.json['message'], "Username/email = " \
           f"{data['email']} already exists!")

    def test_3_unauthorized_attempt(self):
        result = self.simulate_post('/create/user',
                                    json=data, headers=hu1)
        EQ = self.assertEqual
        IN = self.assertIn
        EQ(result.status_code, 401)
        EQ(result.json['message'], "Only CYBEX-P admin can create user!")

        
class OrgAddUserTest(BaseTestCase):
    
    @classmethod
    def setUpClass(cls):
        assert _ID_B.find_one() is None
        make_test_data()        

    @classmethod
    def tearDownClass(cls):
        delete_test_data()
        _ID_B.drop()

    def test_01_add_one_user_to_acl(self):
        o10 = Org('org10', u1, u1, 'Org 10')
        data = {
            'org_hash': o10._hash,
            'user': [u2._hash],
            'add_to': ['acl']
        }
        res = self.simulate_post('/org/add/user', json=data, headers=hu1)
        self.assertEqual(res.status_code, 201)
        o10._update()
        self.assertUserOnlyInAcl(u2, o10)
        o10.delete(delete_children=False)

    def test_02_add_one_str_user_to_acl(self):
        o10 = Org('org10', u1, u1, 'Org 10')
        data = {
            'org_hash': o10._hash,
            'user': u2._hash,
            'add_to': ['acl']
        }
        res = self.simulate_post('/org/add/user', json=data, headers=hu1)
        self.assertEqual(res.status_code, 201)
        o10._update()
        self.assertUserOnlyInAcl(u2, o10)
        o10.delete(delete_children=False)

    def test_03_add_two_user_to_acl(self):
        o10 = Org('org10', u1, u1, 'Org 10')
        data = {
            'org_hash': o10._hash,
            'user': [u3._hash, u2._hash],
            'add_to': ['acl']
        }
        res = self.simulate_post('/org/add/user', json=data, headers=hu1)
        self.assertEqual(res.status_code, 201)
        o10._update()
        self.assertUserOnlyInAcl(u2, o10)
        self.assertUserOnlyInAcl(u3, o10)
        o10.delete(delete_children=False)

    def test_04_error_user_is_in_acl(self):
        EQ = self.assertEqual
        o10 = Org('org10', u1, u1, 'Org 10')
        data = {
            'org_hash': o10._hash,
            'user': [u1._hash],
            'add_to': ['acl']
        }
        res = self.simulate_post('/org/add/user', json=data, headers=hu1)
        EQ(res.status_code, 400)
        EQ(res.json['message'], f"User already in ACL = {u1._hash}!")
        o10.delete(delete_children=False)

    def test_05_add_one_user(self):
        o10 = Org('org10', u1, u1, 'Org 10')
        data = {
            'org_hash': o10._hash,
            'user': [u2._hash],
            'add_to': ['user']
        }
        res = self.simulate_post('/org/add/user', json=data, headers=hu1)
        self.assertEqual(res.status_code, 201)
        o10._update()
        self.assertUserIsInOrg(u2, o10)
        o10.delete(delete_children=False)

    def test_06_add_two_user(self):
        o10 = Org('org10', u1, u1, 'Org 10')
        data = {
            'org_hash': o10._hash,
            'user': [u3._hash, u2._hash],
            'add_to': ['user']
        }
        res = self.simulate_post('/org/add/user', json=data, headers=hu1)
        self.assertEqual(res.status_code, 201)
        o10._update()
        self.assertUserIsInOrg(u2, o10)
        self.assertUserIsInOrg(u3, o10)
        o10.delete(delete_children=False)

    def test_07_error_user_is_in_org(self):
        EQ = self.assertEqual
        o10 = Org('org10', u1, u1, 'Org 10')
        data = {
            'org_hash': o10._hash,
            'user': [u1._hash],
            'add_to': ['user']
        }
        res = self.simulate_post('/org/add/user', json=data, headers=hu1)
        EQ(res.status_code, 400)
        EQ(res.json['message'], f"User already in Org = {u1._hash}!")
        o10.delete(delete_children=False)

    def test_08_add_one_admin(self):
        o10 = Org('org10', u1, u1, 'Org 10')
        data = {
            'org_hash': o10._hash,
            'user': [u2._hash],
            'add_to': ['admin']
        }
        res = self.simulate_post('/org/add/user', json=data, headers=hu1)
        self.assertEqual(res.status_code, 201)
        o10._update()
        self.assertUserIsAdmin(u2, o10)
        o10.delete(delete_children=False)

    def test_09_add_two_admin(self):
        o10 = Org('org10', u1, u1, 'Org 10')
        data = {
            'org_hash': o10._hash,
            'user': [u3._hash, u2._hash],
            'add_to': ['admin']
        }
        res = self.simulate_post('/org/add/user', json=data, headers=hu1)
        self.assertEqual(res.status_code, 201)
        o10._update()
        self.assertUserIsAdmin(u2, o10)
        self.assertUserIsAdmin(u3, o10)
        o10.delete(delete_children=False)

    def test_10_error_user_is_admin(self):
        EQ = self.assertEqual
        o10 = Org('org10', u1, u1, 'Org 10')
        data = {
            'org_hash': o10._hash,
            'user': [u1._hash],
            'add_to': ['admin']
        }
        res = self.simulate_post('/org/add/user', json=data, headers=hu1)
        EQ(res.status_code, 400)
        EQ(res.json['message'], f"User is already admin = {u1._hash}!")
        o10.delete(delete_children=False)

    def test_11_error_missing_org_hash(self):
        EQ = self.assertEqual
        o10 = Org('org10', u1, u1, 'Org 10')
        data = {
##            'org_hash': o10._hash,
            'user': [u2._hash],
            'add_to': ['admin']
        }
        res = self.simulate_post('/org/add/user', json=data, headers=hu1)
        EQ(res.status_code, 400)
        EQ(res.json['message'], "KeyError('org_hash')")
        o10.delete(delete_children=False)

    def test_12_add_acl_user(self):
        o10 = Org('org10', u1, u1, 'Org 10')
        data = {
            'org_hash': o10._hash,
            'user': [u3._hash, u2._hash],
            'add_to': ['acl', 'user']
        }
        res = self.simulate_post('/org/add/user', json=data, headers=hu1)
        self.assertEqual(res.status_code, 201)
        o10._update()
        self.assertUserIsInOrg(u2, o10)
        self.assertUserIsInOrg(u3, o10)
        o10.delete(delete_children=False)

    def test_13_add_user_admin(self):
        o10 = Org('org10', u1, u1, 'Org 10')
        data = {
            'org_hash': o10._hash,
            'user': [u3._hash, u2._hash],
            'add_to': ['user', 'admin']
        }
        res = self.simulate_post('/org/add/user', json=data, headers=hu1)
        self.assertEqual(res.status_code, 201)
        o10._update()
        self.assertUserIsAdmin(u2, o10)
        self.assertUserIsAdmin(u3, o10)
        o10.delete(delete_children=False)

    def test_14_add_user_admin_acl(self):
        o10 = Org('org10', u1, u1, 'Org 10')
        data = {
            'org_hash': o10._hash,
            'user': [u3._hash, u2._hash],
            'add_to': ['user', 'admin', 'acl']
        }
        res = self.simulate_post('/org/add/user', json=data, headers=hu1)
        self.assertEqual(res.status_code, 201)
        o10._update()
        self.assertUserIsAdmin(u2, o10)
        self.assertUserIsAdmin(u3, o10)
        o10.delete(delete_children=False)

    def test_15_add_user_admin_acl_all(self):
        o10 = Org('org10', u1, u1, 'Org 10')
        data = {
            'org_hash': o10._hash,
            'user': [u3._hash, u2._hash],
            'add_to': ['user', 'all', 'admin', 'acl']
        }
        res = self.simulate_post('/org/add/user', json=data, headers=hu1)
        self.assertEqual(res.status_code, 201)
        o10._update()
        self.assertUserIsAdmin(u2, o10)
        self.assertUserIsAdmin(u3, o10)
        o10.delete(delete_children=False)

    def test_16_add_all(self):
        o10 = Org('org10', u1, u1, 'Org 10')
        data = {
            'org_hash': o10._hash,
            'user': [u3._hash, u2._hash],
            'add_to': ['all']
        }
        res = self.simulate_post('/org/add/user', json=data, headers=hu1)
        self.assertEqual(res.status_code, 201)
        o10._update()
        self.assertUserIsAdmin(u2, o10)
        self.assertUserIsAdmin(u3, o10)
        o10.delete(delete_children=False)
        

class OrgInfoTest(BaseTestCase):
    
    @classmethod
    def setUpClass(cls):
        assert _ID_B.find_one() is None
        make_test_data()        

    @classmethod
    def tearDownClass(cls):
        delete_test_data()
        _ID_B.drop()

    def test_return_type_default(self):
        EQ = self.assertEqual
        IN = self.assertIn
        data = {'org_hash': o1._hash}
        res = self.simulate_post('/org/info', json=data, headers=hu1)
        result = res.json['result']
        EQ(res.status_code, 200)
        EQ(len(result), 3)
        EQ(len(result['acl']), 1)
        IN(u1._hash, result['acl'])
        EQ(len(result['admin']), 1)
        EQ(len(result['user']), 1)
        EQ(u1._hash, result['admin'][0]['_hash'])
        EQ(u1._hash, result['user'][0]['_hash'])

    def test_return_type_all(self):
        EQ = self.assertEqual
        IN = self.assertIn

        data = {'org_hash': o1._hash, 'return_type':['all']}
        res = self.simulate_post('/org/info', json=data, headers=hu1)
        result = res.json['result']
        EQ(res.status_code, 200)
        EQ(len(result), 3)
        EQ(len(result['acl']), 1)
        IN(u1._hash, result['acl'])
        EQ(len(result['admin']), 1)
        EQ(len(result['user']), 1)
        EQ(u1._hash, result['admin'][0]['_hash'])
        EQ(u1._hash, result['user'][0]['_hash'])

    def test_return_type_all_str(self):
        EQ = self.assertEqual
        IN = self.assertIn
        data = {'org_hash': o1._hash, 'return_type':'all'}
        res = self.simulate_post('/org/info', json=data, headers=hu1)
        result = res.json['result']
        EQ(res.status_code, 200)
        EQ(len(result), 3)
        EQ(len(result['acl']), 1)
        IN(u1._hash, result['acl'])
        EQ(len(result['admin']), 1)
        EQ(len(result['user']), 1)
        EQ(u1._hash, result['admin'][0]['_hash'])
        EQ(u1._hash, result['user'][0]['_hash'])

    def test_return_type_admin(self):
        EQ = self.assertEqual
        data = {'org_hash': o1._hash, 'return_type':['admin']}
        res = self.simulate_post('/org/info', json=data, headers=hu1)
        result = res.json['result']
        EQ(res.status_code, 200)
        EQ(len(result), 1)
        EQ(len(result['admin']), 1)
        EQ(u1._hash, result['admin'][0]['_hash'])

    def test_return_type_user_str(self):
        EQ = self.assertEqual
        data = {'org_hash': o1._hash, 'return_type':'user'}
        res = self.simulate_post('/org/info', json=data, headers=hu1)
        result = res.json['result']
        EQ(res.status_code, 200)
        EQ(len(result), 1)
        EQ(len(result['user']), 1)
        EQ(u1._hash, result['user'][0]['_hash'])

    def test_return_type_admin_user(self):
        EQ = self.assertEqual
        data = {'org_hash': o1._hash, 'return_type':['admin', 'user']}
        res = self.simulate_post('/org/info', json=data, headers=hu1)
        result = res.json['result']
        EQ(res.status_code, 200)
        EQ(len(result), 2)
        EQ(len(result['admin']), 1)
        EQ(len(result['user']), 1)
        EQ(u1._hash, result['admin'][0]['_hash'])
        EQ(u1._hash, result['user'][0]['_hash'])

    def test_return_type_acl_admin(self):
        EQ = self.assertEqual
        IN = self.assertIn
        data = {'org_hash': o1._hash, 'return_type':['acl', 'admin']}
        res = self.simulate_post('/org/info', json=data, headers=hu1)
        result = res.json['result']
        EQ(res.status_code, 200)
        EQ(len(result), 2)
        EQ(len(result['acl']), 1)
        IN(u1._hash, result['acl'])
        EQ(len(result['admin']), 1)
        EQ(u1._hash, result['admin'][0]['_hash'])


    def test_return_type_admin_all(self):
        EQ = self.assertEqual
        IN = self.assertIn
        data = {'org_hash': o1._hash, 'return_type':['admin', 'all']}
        res = self.simulate_post('/org/info', json=data, headers=hu1)
        result = res.json['result']
        EQ(res.status_code, 200)
        EQ(len(result), 3)
        EQ(len(result['acl']), 1)
        IN(u1._hash, result['acl'])
        EQ(len(result['admin']), 1)
        EQ(len(result['user']), 1)
        EQ(u1._hash, result['admin'][0]['_hash'])
        EQ(u1._hash, result['user'][0]['_hash'])

    def test_user_admin_of_multiple_org(self):
        EQ = self.assertEqual
        IN = self.assertIn
        data = {'org_hash': o2._hash, 'return_type':'all'}
        res = self.simulate_post('/org/info', json=data, headers=hu2)
        result = res.json['result']
        EQ(res.status_code, 200)
        EQ(len(result), 3)
        EQ(len(result['acl']), 2)
        IN(u1._hash, result['acl'])
        IN(u2._hash, result['acl'])
        EQ(len(result['admin']), 1)
        EQ(len(result['user']), 2)
        EQ(u2._hash, result['admin'][0]['_hash'])
        expected_user_hash = [u1._hash, u2._hash]
        for u in result['user']:
            IN(u['_hash'], expected_user_hash)
            expected_user_hash.remove(u['_hash'])


class OrgDelUserTest(BaseTestCase):
    
    @classmethod
    def setUpClass(cls):
        assert _ID_B.find_one() is None
        make_test_data()        

    @classmethod
    def tearDownClass(cls):
        delete_test_data()
        _ID_B.drop()

    def test_01_del_one_user_from_acl(self):
        o10 = Org('org10', [u1, u2, u3], u1, 'Org 10')
        data = {
            'org_hash': o10._hash,
            'user': [u2._hash],
            'del_from': ['acl']
        }
        res = self.simulate_post('/org/del/user', json=data, headers=hu1)
        self.assertEqual(res.status_code, 201)
        o10._update()
        self.assertNotIn(u2, o10._acl)
        o10.delete(delete_children=False)

    def test_02_del_one_str_user_from_acl(self):
        o10 = Org('org10', [u1, u2, u3], u1, 'Org 10')
        data = {
            'org_hash': o10._hash,
            'user': u2._hash,
            'del_from': ['acl']
        }
        res = self.simulate_post('/org/del/user', json=data, headers=hu1)
        self.assertEqual(res.status_code, 201)
        o10._update()
        self.assertNotIn(u2, o10._acl)
        o10.delete(delete_children=False)

    def test_03_del_two_user_from_acl(self):
        o10 = Org('org10', [u1, u2, u3], u1, 'Org 10')
        data = {
            'org_hash': o10._hash,
            'user': [u2._hash, u3._hash],
            'del_from': ['acl']
        }
        res = self.simulate_post('/org/del/user', json=data, headers=hu1)
        self.assertEqual(res.status_code, 201)
        o10._update()
        self.assertNotIn(u2, o10._acl)
        self.assertNotIn(u3, o10._acl)
        o10.delete(delete_children=False)

    def test_04_error_user_is_not_in_acl(self):
        o10 = Org('org10', [u1], u1, 'Org 10')
        data = {
            'org_hash': o10._hash,
            'user': u2._hash,
            'del_from': ['acl']
        }
        res = self.simulate_post('/org/del/user', json=data, headers=hu1)
        EQ = self.assertEqual
        EQ(res.status_code, 400)
        EQ(res.json['message'], f"User is not in ACL = {u2._hash}!")
        o10.delete(delete_children=False)

    def test_05_error_del_acl_user_is_admin(self):
        o10 = Org('org10', [u1,u2], [u1,u2], 'Org 10')
        data = {
            'org_hash': o10._hash,
            'user': u2._hash,
            'del_from': ['acl']
        }
        res = self.simulate_post('/org/del/user', json=data, headers=hu1)
        EQ = self.assertEqual
        EQ(res.status_code, 400)
        EQ(res.json['message'], f"Cannot delete admin from ACL = {u2._hash}!")
        o10.delete(delete_children=False)

    def test_06_del_one_user(self):
        o10 = Org('org10', [u1, u2, u3], u1, 'Org 10')
        data = {
            'org_hash': o10._hash,
            'user': [u2._hash],
            'del_from': ['user']
        }
        res = self.simulate_post('/org/del/user', json=data, headers=hu1)
        self.assertEqual(res.status_code, 201)
        o10._update()
        self.assertUserIsNotInOrg(u2, o10)
        o10.delete(delete_children=False)

    def test_07_del_two_user(self):
        o10 = Org('org10', [u1, u2, u3], u1, 'Org 10')
        data = {
            'org_hash': o10._hash,
            'user': [u2._hash, u3._hash],
            'del_from': ['user']
        }
        res = self.simulate_post('/org/del/user', json=data, headers=hu1)
        self.assertEqual(res.status_code, 201)
        o10._update()
        self.assertUserIsNotInOrg(u2, o10)
        self.assertUserIsNotInOrg(u3, o10)
        o10.delete(delete_children=False)

    def test_08_error_del_user_user_is_not_in_org(self):
        EQ = self.assertEqual
        o10 = Org('org10', [u1], u1, 'Org 10')
        data = {
            'org_hash': o10._hash,
            'user': [u2._hash],
            'del_from': ['user']
        }
        res = self.simulate_post('/org/del/user', json=data, headers=hu1)
        EQ(res.status_code, 400)
        EQ(res.json['message'], f"User is not in org = {u2._hash}!")
        o10.delete(delete_children=False)

    def test_09_err_del_user_user_is_admin(self):
        EQ = self.assertEqual
        o10 = Org('org10', [u1, u2], [u1, u2], 'Org 10')
        data = {
            'org_hash': o10._hash,
            'user': [u2._hash],
            'del_from': ['user']
        }
        res = self.simulate_post('/org/del/user', json=data, headers=hu1)
        EQ(res.status_code, 400)
        EQ(res.json['message'], f"User is admin = {u2._hash}!")
        o10.delete(delete_children=False)

    def test_10_del_one_admin(self):
        o10 = Org('org10', [u1, u2, u3], [u1, u2, u3], 'Org 10')
        data = {
            'org_hash': o10._hash,
            'user': [u2._hash],
            'del_from': ['admin']
        }
        res = self.simulate_post('/org/del/user', json=data, headers=hu1)
        self.assertEqual(res.status_code, 201)
        o10._update()
        self.assertUserIsNotAdmin(u2, o10)
        o10.delete(delete_children=False)

    def test_11_del_two_admin(self):
        o10 = Org('org10', [u1, u2, u3], [u1, u2, u3], 'Org 10')
        data = {
            'org_hash': o10._hash,
            'user': [u2._hash, u3._hash],
            'del_from': ['admin']
        }
        res = self.simulate_post('/org/del/user', json=data, headers=hu1)
        self.assertEqual(res.status_code, 201)
        o10._update()
        self.assertUserIsNotAdmin(u2, o10)
        self.assertUserIsNotAdmin(u3, o10)
        o10.delete(delete_children=False)

    def test_12_error_user_is_not_admin(self):
        EQ = self.assertEqual
        o10 = Org('org10', [u1], u1, 'Org 10')
        data = {
            'org_hash': o10._hash,
            'user': [u2._hash],
            'del_from': ['admin']
        }
        res = self.simulate_post('/org/del/user', json=data, headers=hu1)
        EQ(res.status_code, 400)
        EQ(res.json['message'], f"User is not admin = {u2._hash}!")
        o10.delete(delete_children=False)

    def test_13_error_missing_org_hash(self):
        EQ = self.assertEqual
        o10 = Org('org10', u1, u1, 'Org 10')
        data = {
##            'org_hash': o10._hash,
            'user': [u2._hash],
            'del_from': ['admin']
        }
        res = self.simulate_post('/org/del/user', json=data, headers=hu1)
        EQ(res.status_code, 400)
        EQ(res.json['message'], "KeyError('org_hash')")
        o10.delete(delete_children=False)


class OrgsAdminOfTest(BaseTestCase):
    
    @classmethod
    def setUpClass(cls):
        assert _ID_B.find_one() is None
        make_test_data()        

    @classmethod
    def tearDownClass(cls):
        delete_test_data()
        _ID_B.drop()

    def test_1(self):
        EQ = self.assertEqual
        IN = self.assertIn
        
        res = self.simulate_get('/orgs/admin_of', headers=hu1)
        for i in res.json['result']:
            IN(i['_hash'], [o1._hash])
            
        res = self.simulate_get('/orgs/admin_of', headers=hu3)
        EQ(res.json['result'], [])


class OrgsUserOfTest(BaseTestCase):
    
    @classmethod
    def setUpClass(cls):
        assert _ID_B.find_one() is None
        make_test_data()        

    @classmethod
    def tearDownClass(cls):
        delete_test_data()
        _ID_B.drop()

    def test_1(self):
        EQ = self.assertEqual
        IN = self.assertIn
        
        res = self.simulate_get('/orgs/user_of', headers=hu1)
        for i in res.json['result']:
            IN(i['_hash'], [o1._hash, o2._hash])
            
        res = self.simulate_get('/orgs/user_of', headers=hu3)
        EQ(res.json['result'], [])


class UserInfoSelfTest(BaseTestCase):
    
    @classmethod
    def setUpClass(cls):
        assert _ID_B.find_one() is None
        make_test_data()        

    @classmethod
    def tearDownClass(cls):
        delete_test_data()
        _ID_B.drop()

    def test_1(self):
        EQ = self.assertEqual
        IN = self.assertIn
        
        res = self.simulate_get('/user/info/self', headers=hu1)
        
        EQ(res.json['message'], 'See result.')
        EQ(res.json['result']['itype'], 'object')
        EQ(res.json['result']['sub_type'], 'cybexp_user')
        EQ(res.json['result']['_hash'], u1._hash)
        EQ(res.json['result']['data']['email_addr'][0], 'user1@example.com')
        EQ(res.json['result']['data']['name'][0], 'User 1')
        EQ(len(res.json['result']['_ref']), 2)
        EQ(len(res.json['result']['_cref']), 2)
        



        

        

if __name__ == '__main__':
    unittest.main()
