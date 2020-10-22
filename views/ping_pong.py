import falcon

class PingPong(object):
    def on_get(self, req, resp):
        resp.status = falcon.HTTP_200
        resp.media = {"message" : "pong"}
