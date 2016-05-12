# Influxdb-shim
Implementation of the shim between users and InfluxDB
Includes following functionalities:
* AUTH - user authentication via LDAP
* QUERIES - queries through to backend (InfluxDB) are limited only to those metrics that match user credentials
* LIMITS - query limiter QoS, something like between queries or max number of concurrent request
* PERMS - blacklist of commands users cannot run(```like select * from mem limit 10```)

## Configuration
The shim is configured via flags and conf file

### Flags for configuration

```
Usage of ./influxdb-shim:
  -alsologtostderr
        log to standard error as well as files
  -config string
        config file name without extension (default "conf")
  -configPath string
        config file path (default ".")
  -log_backtrace_at value
        when logging hits line file:N, emit a stack trace (default :0)
  -log_dir string
        If non-empty, write log files in this directory
  -logtostderr
        log to standard error instead of files
  -stderrthreshold value
        logs at or above this threshold go to stderr
  -v value
        log level for V logs
  -vmodule value
        comma-separated list of pattern=N settings for file-filtered logging
```

### Configuration file

Configuations are kept in toml file format, but can be changed to any other.
```toml
[auth]
    [ldap]
        name        = ""        # a name assigned to the new method of authorization
        host        = ""        # example: mydomain.com
        port        = ""        # example: 636
        useTLS      = false     # whether to use TLS when connecting to the LDAP server
        bindDN      = ""        # example: cn=Search,dc=mydomain,dc=com
        bindPasswd  = ""        # the password for the Bind DN
        userBase    = ""        # example: ou=Users,dc=mydomain,dc=com
        userFilter  = ""        # example: (&(objectClass=posixAccount)(uid=%s)), %s param will be substituted with user's username
        userDN      = ""        # example: cn=%s,ou=Users,dc=mydomain,dc=com
        useBindDN   = false     # using bindDN authentication
        attrUsername= ""
        attrName    = ""
        attrSurname = ""
        attrMail    = ""        # the attribute of the user's LDAP record containing email address, example: email

[influxdb]
    addr        = "127.0.0.1:8086"
    username    = ""
    password    = ""
    userAgent   = ""
[web]
    addr        = "127.0.0.1:8888"
[blacklist]
    queries     = [""]      # blacklist of queries that is prohibitied to run, example: "SHOW DATABASES"
    adminGroup  = "admin"   # admin group name, this group members can see & run everything
    [groups]                # group specifications, group members have allowed and denied query list 
        [global]            # sample group
            allowed = [
                ""
            ]
            denied = [
                ""
            ]
```
