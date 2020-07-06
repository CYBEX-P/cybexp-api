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


### Routes
app.add_route('/query', views.Query())
app.add_route('/raw', views.Raw())


### Test Windows >> hupper -m api
import os
if __name__ == '__main__' and os.name == 'nt':
    from wsgiref import simple_server
    httpd = simple_server.make_server('127.0.0.1', 5000, app)
    httpd.serve_forever()
