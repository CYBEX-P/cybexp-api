"""CYBEXP API."""

import falcon
import logging
 
import tahoe
from tahoe.identity import IdentityBackend, Identity

import loadconfig, resource, views


# Logging
# -------

logging.basicConfig(filename = 'api.log') 
logging.basicConfig(level=logging.ERROR,
    format='\n\n%(asctime)s %(levelname)s: File %(filename)s,' \
        ' line %(lineno)s in %(funcName)s \n%(message)s')


def configureIDBackend(_id_backend, secret="secret"):
    """Configures identity backend."""
    
    resource.common.configureIDBackend(_id_backend, secret)


def configureCacheDB(file_entries, fs):
    """Configures cache backend."""
    
    views.raw.configureCacheDB(file_entries, fs)

def configureReportBackend(_report_backend):
    """Confgiures report backend."""

    views.query.configureReportBackend(_report_backend)



# Temporary Fix
# -------------

_id_backend = loadconfig.get_identity_backend()
configureIDBackend(_id_backend)

file_entries, fs = loadconfig.get_cache_db()
configureCacheDB(file_entries, fs)

_report_backend = loadconfig.get_report_backend()
configureReportBackend(_report_backend)



# Initialize API
# --------------

app = falcon.App()


# Views
# -----

app.add_route('/ping', views.PingPong())
app.add_route('/query', views.Query())
app.add_route('/raw', views.Raw())


# Resource (Identity/User/Org/Config)
# -----------------------------------

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

    _id_backend, secret = loadconfig.get_identity_backend()
    configureIDBackend(_id_backend, secret)

    file_entries, fs = loadconfig.get_cache_db()
    configureCacheDB(file_entries, fs)

    _report_backend = loadconfig.get_report_backend()
    configureReportBackend(_report_backend)
    
    from wsgiref import simple_server
    httpd = simple_server.make_server('0.0.0.0', 5000, app)
    httpd.serve_forever()










    
