# certmgr

certmgr is a tool for managing certificates using CFSSL. It does the
following:

* Ensures certificates are present.
* Renews certificates before they expire.
* Triggering a service reload or restart on certificate updates.

It operates on **certificate specs**, which are JSON files containing
the information needed to generate a certificate. These are currently
JSON due to the way CFSSL works; a future update can add YAML tags to
the relevant CFSSL structures to allow these to be YAML files.

If a certificate can't be renewed (i.e. there's a problem talking to
the CA), the certificate is kept in the renewal queue and will be
attempted later.

When run without any subcommands, certmgr will start monitoring
certificates. The configuration and specifications can be validated
using the `check` subcommand.

**Note**: due to a [bug](https://github.com/golang/go/issues/19395) in
the os/user package, `certmgr` requires Go 1.9 or later to use the
user/group functionality in file specifications.

## Web server

When appropriately configured, `certmgr` will start a web server that
has the following endpoints:

* `/` is a basic overview page with links to the other endpoints and a
  snapshot of the current metrics values.
* `/metrics` is the Prometheus endpoint (see the Metrics section).
* `/debug/pprof` is a
  [net/http/pprof](https://golang.org/pkg/net/http/pprof/) endpoint.

In the configuration file, the `index_extra_html` may contain HTML
that will be inserted at the top of the file, after the server start
time and current host:port.

## Metrics

The following metrics are collected by Prometheus:

* `cert_watching` (counter): this is the number of certificates being
  watched by certmgr.
* `cert_renewal_queue` (gauge): this is the current number of
  certificates waiting to be renewed.
* `cert_next_expires` (gauge): this contains the number of hours to
  the next certificate expiration.
* `cert_renewal_failures` (counter): this counts the number of
  failures to renew a certificate.

## certmgr.yaml

The configuration file is a YAML file; it is expected to be in
`/etc/certmgr/certmgr.yaml`. The location can be changed using the
`-f` flag.

An example `certmgr.yaml` file is:

```
dir: /etc/certmgr.d
default_remote: ca.example.net:8888
svcmgr: systemd
before: 72h
interval: 30m

metrics_port: 8080
metrics_address: localhost

index_extra_html: |
  <hr>
  <p>Links:</p>
  <ul>
    <li><strong><a href="https://internal.corp/sys/certmgr/runbook">Service runbook</a></strong></li>
	<li><a href="https://internal.corp/sys/certmgr">Component homepage</a></li>
	<li><a href="https://internal.corp/sys/ca">Internal CA documentation</a></li>
	<li><a href="https://certs.prometheus.internal.corp/alerts">Current TLS-related alerts</a></li>
  </ul>
  <hr>
```

This contains all of the currently available parameters:

* `dir`: this specifies the directory containing the certificate specs
* `svcmgr`: this specifies the service manager to use for restarting
  or reloading services. This can be `systemd` (using `systemctl`),
  `sysv` (using `service`), `circus` (using `circusctl`), or `dummy`
  (no restart/reload behavior).
* `before`: this is the interval before a certificate expires to start
  attempting to renew it.
* `interval`: this controls how often to check certificate expirations
  and how often to update the `cert_next_expires` metric.
* `metrics_address`: specifies the address for the Prometheus HTTP
  endpoint.
* `metrics_port`: specifies the port for the Prometheus HTTP endpoint.
* `index_extra_html`: specifies additional links that may be
  site-specific (such as the runbook) for the service index page.

## Certificate Specs

An example certificate spec:

```
{
    "service": "nginx",
    "action": "restart",
    "request": {
        "CN": "www.example.net",
        "hosts": [
            "example.net",
            "www.example.net"
        ],
        "key": {
            "algo": "ecdsa",
            "size": 521
        },
        "names": [
            {
                "C": "US",
                "ST": "CA",
                "L": "San Francisco",
                "O": "Example, LLC"
            }
        ]
    },
    "private_key": {
        "path": "/etc/ssl/private/www.key",
        "owner": "www-data",
        "group": "www-data",
        "mode": "0600"
    },
    "certificate": {
        "path": "/home/kyle/tmp/certmgr/certs/test1.pem",
        "owner": "www-data",
        "group": "www-data"
    },
    "authority": {
        "remote": "ca.example.net:8888",
        "auth_key": "012345678012345678",
        "label": "www_ca",
        "profile": "three-month",
        "file": {
            "path": "/etc/myservice/ca.pem",
            "owner": "www-data",
            "group": "www-data"
        }
    }
}
```

A certificate spec has the following fields:

* `service`: this is optional, and names the service that the `action`
  should be applied to.
* `action`: this is optional, and may be one of "restart", "reload",
  or "nop".
* `request`: a CFSSL certificate request (see below).
* `private_key` and `certificate`: file specifications (see below) for
  the private key and certificate.
* `authority`: contains the CFSSL CA configuration (see below).

File specifications contain the following fields:

* `path`: this is required, and is the path to store the file.
* `owner`: this is optional; if it's not provided, the current user is
  used.
* `group`: this is optional; if it's not provided, the primary group
  of the current user is used.
* `mode`: this is optional; if it's not provided, "0644" will be
  used. It should be a numeric file mode.

CFSSL certificate requests have the following fields:

* `CN`: this contains the common name for the certificate.
* `hosts`: this is a list of SANs and/or IP addresses for the
  certificate.
* `key`: this is optional; it should contain an "algo" of either "rsa"
  or "ecdsa" and a "size" appropriate for the chosen
  algorithm. Recommendations are "rsa" and 2048 or "ecdsa"
  and 256. The default is "ecdsa" and 256.
* `names`: contains PKIX name information, including the "C"
  (country), "ST" (state), "L" (locality/city), "O" (organisation),
  and "OU" (organisational unit) fields.

The CA specification contains the following fields:

* `remote`: the CA to use. If not provided, the default remote from
  the config file is used.
* `auth_key`: the authentication key used to request a certificate.
* `label`: the CA to use for the certificate.
* `profile`: the CA profile that should be used.
* `file`: if this is included, the CA certificate will be saved here. It
  follows the same file specification format above.

## Subcommands

In addition to the certificate manager, there are a few utility
functions specified:

* `check`: validates the configuration file and all the certificate
  specs available in the certificate spec directory.
* `clean`: removes all of the certificates and private keys specified
  by the certificate specs.
* `ensure`: attempts to load all certificate specs, and ensure that
  the TLS key pairs they identify exist, are valid, and that they are
  up-to-date.
* `genconfig`: generates a default configuration file and ensures the
  default service directory exists.
* `version`: prints certificate manager's version, the version of Go
  it was built with, and shows the current configuration.

## See also

The `certmgr` spec is included as `SPEC.rst`.
