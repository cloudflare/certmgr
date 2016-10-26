Certificate Manager Functional Spec
===================================

Summary
-------

certmgr provides transparent on-disk certificate management, including
generation and renewal.

Requirements & Assumptions
--------------------------

Production requirements
~~~~~~~~~~~~~~~~~~~~~~~

#. certmgr should be something that can be easily deployed with Salt (or
   other configuration management) or in Docker containers.
#. Users should only need to specify some metadata for the certificate
   they need.
#. It cannot get in the way of users --- users should be able to point
   certmgr to the spec describing their certificate and let certmgr take
   over from there.
#. It should provide some mechanism for configuration and spec
   validation that emits actionable, human-readable error messages.
   Armed only with the README (or other internal service documentation)
   and the output of this validation, a user should be able to remedy
   configuration issues.

Technical Requirements
~~~~~~~~~~~~~~~~~~~~~~

#. certmgr must be able to generate TLS key pairs from an easily
   understood specification file.
#. certmgr must be able to automatically renew certificates.
#. certmgr must be able to signal services that certificates have
   renewed.
#. certmgr must accomplish the above transparently to users. This is
   somewhat subjective; for example, the user will need to supply some
   basic name information, but this will most likely have to come from
   some sort of internal documentation.

Analytics Requirements
~~~~~~~~~~~~~~~~~~~~~~

The following metrics should be provided by the certificate manager:

-  Time to next expiring certificate
-  Number of failures
-  How many certificates are in the queue

Of these metrics, the following conditions should be considered worthy
of an alert:

-  Time to next expiry falling inside of some threshold value (which
   indicates repeated failures of the renewal queue).
-  The **rate** of increase of new failures indicating a potential
   failure with the CA that isn't a transient network issue.
-  The queue size remaining the same over a threshold period of time.
   This indicates repeated failures to renew certificates in the queue.

Assumptions on Scope
~~~~~~~~~~~~~~~~~~~~

The first iteration of the certificate manager will not attempt to
address the case where a key pair is managed outside of this system
(e.g. in Salt stack); while certmgr can renew these certs in the first
version, it won't submit a PR to update the upstream or notify anyone on
certificate renewals.

Certificate manager currently only works with a CFSSL CA; other CA APIs
are not supported at this time.

It will not watch the directory containing certificate specifications;
the daemon must be reloaded to reload certificate specs.

The first version will not check the certificate spec against an
existing certificate; the presence of the certificate will be the only
check.

System Design
-------------

The certificate manager is essentially a frontend for the `transport
package <https://godoc.org/github.com/cloudflare/cfssl/transport>`__
that runs on a host and watches multiple certificates. It should do the
following:

#. Maintain a queue of certificates pending renewal, handling those with
   an appropriate backoff as needed in the event of an error.

#. Generate private keys and request certificates for keypairs that are
   missing on disk.

#. Provide support for notifying services (via \`systemctl\`,
   \`circusctl\`, or \`service\`) on certificate renewal; this either
   reloads or restarts the service.

The main program should be configured using a standard configuration
file syntax; as a technical details, the CLI tool and configuration file
frameworks that certmgr will use transparently support both JSON and
YAML. Similarly, the specs should follow the same standard. Given that
the configuration file framework transparently allows either format,
certificate manager should also support certificate specs written in
either format.

If configured with a metrics address and port, certificate manager will
start a web server on those ports with the following endpoints:

-  ``/``: a human readable page that displays what the server belongs to
   (e.g. that this is a certificate manager instance), a snapshot of the
   current metrics, and a link to the other endpoints.

-  ``/metrics``: serves the Prometheus metrics endpoint.

-  ``/debug/pprof``: provides a Go
   `pprof <https://golang.org/pkg/net/http/pprof/>`__ HTTP endpoint for
   debugging.

Subcommands
~~~~~~~~~~~

The following subcommands should be provided:

#. **check**: this should verify the configuration. A user who runs this
   should have high confidence that their configuration is set up
   properly. There is one exception to this: the only way to verify
   CFSSL authentication keys at this time is to request a certificate.
   There is an implicit assumption being made here that we should not
   request a certificate until a renewal is required.

#. **genconfig**: this should generate a default configuration file and
   create the certificate spec directory. This is useful for seeing what
   certificate manager expects.

Interoperability
----------------

Certificate manager currently works only with a CFSSL CA.

Supportability
--------------

Failure modes
~~~~~~~~~~~~~

Broadly speaking, the certificate manager will fail in one of two cases:
at startup, due to configuration file errors, or at runtime.

Configuration failures
^^^^^^^^^^^^^^^^^^^^^^

Certificate manager will fail at startup in the case of invalid
configuration files. In general, service managers will not return a
failure in this case unless ``certmgr check`` is given as a pre-command
(e.g. systemd's ``ExecStartPre`` directive). It is highly recommended to
add this check to the service manager configuration. Note that the
``check`` subcommand only catches the first error.

Configuration errors should, by design, be caught by the ``check``
subcommand. A configuration error that survives ``check`` should be
considered a design failure. The exception to this is that certificate
manager cannot validate CFSSL authentication keys until the certificate
renewal process. If a certificate spec uses an invalid authentication
key, this (in the current CFSSL design) cannot be caught until renewal
time.

#. An invalid configuration file will cause certmgr to not start.

#. Certificate manager will currently not start if no certificate specs
   are provided; this condition includes the case where the certificate
   specification directory does not exist.

#. Certificate manager will try to fetch the CA's certificate via the
   CFSSL info endpoint on startup; if this CA can't be reached,
   certificate manager will fail.

#. If the authentication key for a CA is invalid, certificate manager
   will shut down. This design choice was made to force operations
   intervention, as there is no mechanism for automatically fixing this.

Runtime failures
^^^^^^^^^^^^^^^^

During operation, there are several failure scenarios; these all occur
during certificate renewal.

The number of failures is exported as the Prometheus counter
``cert_renewal_failures``, and the number of certificates pending
renewal is exported as the Prometheus gauge ``cert_renewal_queue``.
These are both alertable metrics, triggering on an increased number of
``cert_renewal_failures`` over a short period of time or a non-zero
``cert_renewal_queue`` that persists (indicative of the queue not
clearing).

#. During certificate renewal, the CA might be unavailable. The renewal
   queue uses a per-certificate
   `backoff <https://github.com/cloudflare/backoff/>`__ mechanism.

#. During certificate renewal, disk I/O (or some other operating system
   error) could prevent the updated certificate from being written to
   disk.

#. If the key pair has to be generated, the generation process may fail.

#. If configured, the service that is supposed to be notified of the
   change may fail to reload or restart.

Logging
~~~~~~~

Certificate manager uses the Go standard library's logging package (via
the `CFSSL log package <https://godoc.org/github.com/cloudflare/cfssl/log>`__). If
started in debug mode, it will emit debug messages. Otherwise, it logs
informational levels.

Security
--------

The certificate manager will require root permissions if it is to
perform the following actions:

+ Set permissions and ownership on the generated certificate and keys
  (e.g. using ``chmod`` / ``chown``)
+ Reload and restart services using the service manager.

Any service running as root always warrants deeper scrutiny, and it
may make sense to run this service in a chroot.

There isn't any validation done on the output paths in this version;
this could cause an overwrites if the wrong path is given.

Operating system protections are relied upon heavily in the following
cases:

#. The TLS private keys are stored on disk without any password or
   protection; this is due to the fact that most services using these
   can't handle an automatic reload or restart with password-protected
   keys.

#. The authentication keys for the CAs are in plaintext as part of the
   certificate specs.

Avenues for Future Improvements
-------------------------------

Based on operational experience, the following limitations should be
considered and a decision made whether it is sufficiently useful to have
the following features and whether to dedicate development resources to
building out these improvements.

Live updating of certificate specs
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Certificate manager could watch the certificate specification directory
and update its list of managed certificates accordingly. Note that the
removal of a specification would also need to trigger the removal of
that certificate from the queue if it is in processing.

Live reloading of the certificate manager configuration
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The configuration file framework supports doing this, but it would
require effort to make sure the configuration is in sync with the
running server.

Support for external notifications
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

It might be useful, particularly in the cases of externally-managed
certificates or interactions with external monitoring services, to send
notifications on certificate update. This could take the form of web
hooks; if this turns out to be a desired feature, stakeholders should
block out time to present requirements for this system.

A thorough check subcommand
~~~~~~~~~~~~~~~~~~~~~~~~~~~

As it stands, the check subcommand performs all of the setup before
starting the server itself, and therefore fails at the first error; it
won't report all of the problems with the configuration file if there
are multiple.

Key rolling
~~~~~~~~~~~

The current implementation doesn't re-generate the private key when
renewing the certificate. It might be useful to implement an automatic
key rolling system (e.g., force regenerating the key every time, every n
renewals, after some time t, etc...).
