#### Run on Windows
```
hupper -m api
```


## deployment 

```bash
source env/bin/activate
#install dependency
pip install uwsgi

# run 
/path/to/env/bin/uwsgi --init uwsgi.init
```
