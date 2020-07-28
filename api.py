"""CYBEXP API."""

import falcon
import logging

### Logging
#logging.basicConfig(filename = 'api.log') 
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

### Routes
app.add_route('/query', views.Query())
app.add_route('/raw', views.Raw())

tk_name = "m"
app.add_route('/{tk_name}/{var1}/{var2}',resource.TokenManager())
app.add_route('/{tk_name}/{var1}',resource.TokenManager())

### Test Windows >> hupper -m api
import os
if __name__ == '__main__' :
    from wsgiref import simple_server
    httpd = simple_server.make_server('127.0.0.1', 5000, app)
    httpd.serve_forever()
