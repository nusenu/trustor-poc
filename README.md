
This is a partial and quick and dirty proof of concept implementation of
the following specifications to configure a tor client to use trusted exit relays only.


* https://nusenu.github.io/ContactInfo-Information-Sharing-Specification/#proof
* https://gitlab.torproject.org/tpo/core/torspec/-/blob/main/proposals/326-tor-relay-well-known-uri-rfc8615.md
* https://nusenu.github.io/tor-relay-operator-ids-trust-information (WIP DRAFT)


**NOTE: This PoC is NOT fit for general use and not meant to be used by end-users!**

This limited version only selects exit relays and leaves other positions unchanged.
It supports a `max_depth` of 0 [only](https://nusenu.github.io/tor-relay-operator-ids-trust-information/#trust-information-consumers) (no recusion to find trusted operators).


## this PoC performs the following steps

* reads the trust configuration and validation cache
* connects to a local tor client via it's ControlPort to find relays claiming to be from a trusted operator
* validates claims via HTTPS (routed via tor) or DNS including DNSSEC check (can also be routed via tor but requires dnscrypt-proxy)
* writes a validation cache to disk
* configures the local tor client (non-persistently) to only use exits from trusted operators that passed the validation steps


## requirements

* a local tor client must be running (see sample torrc file)
* `dnssec-root-trust` must contain the DNSSEC Root Trust Anchor ([IANA](https://www.iana.org/dnssec/files))
* local dnscrypt-proxy daemon, configured to route (encrypted) DNS via tor's SOCKSPort

```
force_tcp = true

proxy = 'socks5://127.0.0.1:9050'

...
```

## configuration

* this PoC comes with an empty trust_config file, users need to add entries ([example](https://github.com/nusenu/trustor-example-trust-config/blob/main/trust_config))
* dnscrypt-proxy is expected to listen on 127.0.2.1:53 otherwise configure the IP address in the resolv.conf file
* generate a password hash via `tor --hash-password randomstringgoeshere` and paste it into the torrc config (or use `ControlSocket` instead)
* add the plaintext password to the `controller_password=` line in the script
* [torcontactinfoparser](https://github.com/erans/torcontactinfoparser) needs to be installed manually
* on debian pyunbound is in the [python3-unbound](https://packages.debian.org/bullseye/python3-unbound) package


## used libraries

* [stem](https://stem.torproject.org/)
* [torcontactinfoparser](https://github.com/erans/torcontactinfoparser)
* [pyunbound](https://www.nlnetlabs.nl/documentation/unbound/pyunbound/) for DNSSEC validation 
* requests (with pysocks support)
* urllib
