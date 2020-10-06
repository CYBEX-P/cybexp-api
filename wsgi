import os
import api

# # Replace with your app's method of configuration
# config = myproject.get_config(os.environ['MYPROJECT_CONFIG'])
# # uWSGI will look for this variable
# application = myproject.create_api(config)

appication = api.app
