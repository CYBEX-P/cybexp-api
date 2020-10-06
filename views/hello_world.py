import falcon
import time
import logging


class HelloWorld(object):
    def on_get(self, req, resp):
        resp.status = falcon.HTTP_200  # This is the default status
        resp.body = ('hello world ;)\n')
