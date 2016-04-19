# ldap-auth
Implementation of the shim between users and InfluxDB
Includes following functionalities:
* AUTH - user authentication via LDAP
* QUERIES - queries through to backend (InfluxDB) are limited only to those metrics that match user credentials
* LIMITS - query limiter QoS, something like between queries or max number of concurrent request
* PERMS - blacklist of commands users cannot run(```like select * from mem limit 10```)
