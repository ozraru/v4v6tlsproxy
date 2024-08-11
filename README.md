# v4v6tlsproxy
proxy TLS connection from IPv4 to IPv6

## Workflow
1. Listen TLS connection
2. Parse TLS Client Hello and extract destination hostname from SNI(Server Name Indication)
3. Check whether destination is allowed or not (if not allowed, close connection immediately)
4. lookup destination hostname and open TCP socket
5. Pass original TLS Client Hello to destination
6. Copy all packet between from/to client/destination

### destination allow setting

#### Domain whitelist  
You can specify allowed destination hostname as plaintext or regular expression.  

It is not recommended to add host which is not administrated by you.  
Your server address appears as the source of the connection to the destination, so you will have legal exposure.

#### IPv4 record
You can specify IPv4 address of your server.
It should be match to A record.

This is useful to provide reverse proxy to many services.
If you don't want this server to be used by not known service, don't use this feature.

## How to use
1. Copy `config.template.yaml` to `config.yaml`
2. Read and edit `config.yaml`
3. (if you choose IPv4 record for allow method) Add A record in addition to origin AAAA record
4. Run this program

