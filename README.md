# What is SRX-Golden-Config Tool ?

SRX-Golden-Config is a tool to create Golden configuration for Advanced Services on SRX. It includes:

* Basic network configuration for L3, Secure Wire and Sniffer mode deployement
* UTM features like Enhanced Web Filtering, Anti-Virus and Anti-Spam
* IDP 
* Sky ATP
* Security Intelligence
* SSL Forward Proxy
* Active Directory

# What version of JunOS is required?

It is designed to be use with JunOS 18.2+. It can still be helpful with older version but some CLI may not be available.

# What are the Juniper SRX requirements? 

It depends of the features you are going to try:

  * __IDP__: Require an IDP license and latest sigpak (donwload from the device or offline update).
  * __UTM__: require AV/AS/WF license. 
  * __Sky ATP/SecInetl__: Require an ATP license and te device need to be enrolled after the configuration is applied.
  * __SSL Proxy__: Require CA certificates and local certifiate to be installed.

# How to use it?

## localy

```shell
> git clone https://github.com/danymello/srx-golden-config
> pip install -r requirements.txt
> python app.py
```

Open your web browser and connect to port 8080. 

## Docker 

__To start image with a local build:__

```shell
> docker build . -t srx_gen

> docker run -d -p 8080:8080 srx_gen
bcd9713e623041e86fd6040b59fa85bea3aa4683add5c0a0c5398172d7ffc6c9

> docker ps
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS                    NAMES
bcd9713e6230        srx_gen             "python app.py"     2 seconds ago       Up 2 seconds        0.0.0.0:8080->8080/tcp   xenodochial_lovelace
```

To start instance with a pre-built image:

```shell
> docker run -d -p 8080:8080 inetsix/srx_gen
```


Please report any issues.