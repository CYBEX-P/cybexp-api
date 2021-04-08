"""CYBEXP API."""

import falcon
import logging
 
import tahoe
from tahoe.identity import IdentityBackend, Identity


# Logging
# -------

##logging.basicConfig(filename = 'api.log') 
logging.basicConfig(
    level=logging.ERROR,
    format='%(asctime)s %(levelname)s %(filename)s:%(lineno)s' \
    ' - %(funcName)() --  %(message)s'
    )


# Initialize Backends
# -------------------

import loadconfig
_ID_B = loadconfig.get_identity_backend()  


# Initialize API
# --------------

app = falcon.App()


# Views
# -----
import views

app.add_route('/ping', views.PingPong())
app.add_route('/query', views.Query())
app.add_route('/raw', views.Raw())


# Resource (Identity/User/Org/Config)
# -----------------------------------
import resource

resource.common.setupIDBackend(_ID_B)

app.add_route('/create/org', resource.CreateOrg())
app.add_route('/create/user', resource.CreateUser())
app.add_route('/org/add/user', resource.OrgAddUser())
app.add_route('/org/info', resource.identity.OrgInfo())
app.add_route('/org/del/user', resource.OrgDelUser())
app.add_route('/orgs/admin_of', resource.identity.OrgsAdminOf())
app.add_route('/orgs/user_of', resource.identity.OrgsUserOf())
app.add_route('/user/info/self', resource.identity.UserInfoSelf())




# Run the API >> hupper -m api
# =============================

if __name__ == '__main__':
    from wsgiref import simple_server
    httpd = simple_server.make_server('0.0.0.0', 5000, app)
    httpd.serve_forever()



# Functions to setup Backend for unittest
# =======================================

def setupTestBackend():
    from tahoe.tests.identity.test_backend import setUpBackend

    _id_backend = setUpBackend()
    assert _id_backend.find_one() is None
    resource.common.setupIDBackend(_id_backend)
    return _id_backend

def tearDownTestBackend(_id_backend):
    tahoe.tests.identity.test_backend.tearDownBackend(_id_backend)
    












#app.add_route('/hello', views.HelloWorld())

# tk_name = "m"
# app.add_route('/{tk_name}/add/config',resource.AddConfig())

# app.add_route('/{tk_name}/{var1}/{var2}',resource.TokenManager())
# app.add_route('/{tk_name}/{var1}',resource.TokenManager())


##app.add_route('/test/token', resource.TokenTest(ident_backend=idnt_bnd))
##app.add_route('/get/my/hash', resource.GetMyHash(ident_backend=idnt_bnd))
##app.add_route('/login', resource.Login(ident_backend=idnt_bnd))
##app.add_route('/logout', resource.Logout(ident_backend=idnt_bnd))

##app.add_route('/add/org', resource.RegisterOrg(ident_backend=idnt_bnd))
##app.add_route('/add/config', resource.AddConfig(ident_backend=idnt_bnd))
##
##app.add_route('/change/org/acl', resource.ChangeACL(ident_backend=idnt_bnd))




    
