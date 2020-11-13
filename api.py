"""CYBEXP API."""

import falcon
import logging

import sys
sys.path.insert(1, '/home/nacho/Projects/tahoe0.7-dev/')
import tahoe
from tahoe.identity import IdentityBackend, Identity




### Logging
##logging.basicConfig(filename = 'api.log') 
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s %(levelname)s %(filename)s:%(lineno)s' \
    ' - %(funcName)() --  %(message)s'
    )


### Initialize API
app = falcon.App()


### Views
import views
import resource

DEBUG =False

if DEBUG:
   ident_mongo_url="mongodb://localhost"
   idnt_bnd = IdentityBackend(mongo_url=ident_mongo_url, create=False)
   Identity._backend = idnt_bnd 
else:
   import loadconfig
   idnt_bnd = loadconfig.get_identity_backend()
   Identity._backend = idnt_bnd

### Routes
app.add_route('/ping', views.PingPong())
app.add_route('/query', views.Query(ident_backend=idnt_bnd))
app.add_route('/raw', views.Raw())




#app.add_route('/hello', views.HelloWorld())

# tk_name = "m"
# app.add_route('/{tk_name}/add/config',resource.AddConfig())

# app.add_route('/{tk_name}/{var1}/{var2}',resource.TokenManager())
# app.add_route('/{tk_name}/{var1}',resource.TokenManager())


app.add_route('/test/token', resource.TokenTest(ident_backend=idnt_bnd))
app.add_route('/get/my/hash', resource.GetMyHash(ident_backend=idnt_bnd))
app.add_route('/login', resource.Login(ident_backend=idnt_bnd))
# app.add_route('/logout', resource.Logout(ident_backend=idnt_bnd))
app.add_route('/add/user', resource.RegisterUser(ident_backend=idnt_bnd))
app.add_route('/add/org', resource.RegisterOrg(ident_backend=idnt_bnd))
app.add_route('/add/config', resource.AddConfig(ident_backend=idnt_bnd))

app.add_route('/change/org/acl', resource.ChangeACL(ident_backend=idnt_bnd))


# Test Windows >> hupper -m api
# Run the API
if __name__ == '__main__':
    from wsgiref import simple_server
    httpd = simple_server.make_server('0.0.0.0', 5000, app)
    httpd.serve_forever()


    
