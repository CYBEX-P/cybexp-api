



# CYBEX-P API Module

<figure class="image">
  <img src="https://user-images.githubusercontent.com/24872576/122102903-cceb6980-cdca-11eb-980f-cd8e1e0079be.png"     width="400" alt="CYBEX-P System Infrastructure">
  <figcaption>Fig 1. CYBEX-P System Infrastructure</figcaption>
</figure>

CYBEX-P backend has 5 software modules --
    1. API
    2. Input
    3. Archive
    4. Analytics
    5. Report

The API module (4, 5 in Fig. 1) consists of the API server (4) and the cache data lake (5). It acts as the gateway
for all data into and out of CYBEX-P. It has two sub-modules –
		1. Data Input sub-module: The input module posts the raw data to the API `\raw` endpoint. The API encrypts the data with the public key of the archive server (6.1) and stores the encrypted data in the cache data lake (5). We have placed the API in the demilitarized zone (DMZ) of our frewall, because it faces the internet. However, storing data in the DMZ is somewhat risky. So, we encrypt the cache data lake with the public key of the archive server. The archive server is in the inside zone. This design protects that data even if the DMZ is compromised.
		2 Report Publishing sub-module. A user can request diﬀerent reports via the API. The API gets those reports from the report DB (8) and presents them to the user. Thus, the API module acts as an interface for all data.
		

### Install & Test Run

1. Download & install [Python 3.9.x](https://www.python.org/downloads/).

2. Create and activate Python virtual environment [(official documentation)](https://docs.python.org/3/library/venv.html). \
Create: ```python -m venv myenv``` \
Activate in *Ubuntu*: ```source myenv/bin/activate``` \
Activate in *Windows*: ```source myenv/Scripts/activate```

3. Download the files from this repository into the server host.
```git clone https://github.com/CYBEX-P/cybexp-api.git```

4. Install external dependencies
```
cd cybexp-api
pip install -r requiremnts.txt
```

5. Download and install TAHOE
```
cd ..
git clone https://github.com/CYBEX-P/tahoe
cd tahoe
python setup.py install
```

6. Unittest
```
cd ../cybexp-api
python -m unittest
```

7. Test Run
```
hupper -m api
curl http://localhost:5000/ping
```



### Deployment on Ubuntu

```bash
source env/bin/activate
#install dependency
pip install uwsgi
# do not install uwsgi via reposiroty, use pip to install in env

# run api with WSGI protocol, use proxy to hook into it or change socket= to http=
/path/to/env/bin/uwsgi --init uwsgi.init
```
