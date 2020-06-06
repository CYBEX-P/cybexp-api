import falcon, logging, pdb

# Logging
#logging.basicConfig(filename = 'api.log')
logging.basicConfig(level=logging.DEBUG)
logging.basicConfig(format='%(asctime)s %(levelname)s:%(message)s')

# Load Config
import loadconfig

# Initialize API
app = falcon.App()

# Views
import views

# Routes
app.add_route('/query', views.Query())
app.add_route('/raw', views.Raw())


# Test Windows >> hupper -m api
from wsgiref import simple_server
if __name__ == '__main__':
  httpd = simple_server.make_server('127.0.0.1', 5000, app)
  httpd.serve_forever()
