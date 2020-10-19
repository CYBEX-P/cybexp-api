#### Run on Windows
```
hupper -m api
```


## deployment 

```bash
source env/bin/activate
#install dependency
pip install uwsgi
# do not install uwsgi via reposiroty, use pip to install in env

# run api with WSGI protocol, use proxy to hook into it or change socket= to http=
/path/to/env/bin/uwsgi --init uwsgi.init
```
