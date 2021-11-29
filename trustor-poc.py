#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
from unbound import ub_ctx,RR_TYPE_TXT,RR_CLASS_IN
from stem.control import Controller
from stem.util.tor_tools import *
from urllib.parse import urlparse
import requests
import datetime

# download this python library from
# https://github.com/erans/torcontactinfoparser
#sys.path.append('/home/....')
from torcontactinfo import *

# tor ControlPort password
controller_password=''
# tor ControlPort IP 
controller_address = '127.0.0.1'
# socks proxy used for outbound web requests (for validation of proofs)
proxy = {'https':'socks5h://127.0.0.1:9050'}

validation_cache_file = 'validation_cache'
dnssec_DS_file = 'dnssec-root-trust'

# we use this UA string when connecting to webservers to fetch rsa-fingerprint.txt proof files
# https://nusenu.github.io/ContactInfo-Information-Sharing-Specification/#uri-rsa
headers = {'User-Agent':'Mozilla/5.0 (Windows NT 10.0; rv:91.0) Gecko/20100101 Firefox/91.0'}

# this is not the system wide /etc/resolv.conf
# use dnscrypt-proxy to encrypt your DNS and route it via tor's SOCKSPort
libunbound_resolv_file = 'resolv.conf'

# for now we support max_depth = 0 only
# this PoC version has no support for recursion
# https://github.com/nusenu/tor-relay-operator-ids-trust-information#trust-information-consumers
supported_max_depths = ['0']

# https://github.com/nusenu/ContactInfo-Information-Sharing-Specification#ciissversion
accepted_ciissversions = ['2']

# https://github.com/nusenu/ContactInfo-Information-Sharing-Specification#proof
accepted_proof_types = ['uri-rsa','dns-rsa']

# https://stackoverflow.com/questions/2532053/validate-a-hostname-string
# FIXME this check allows non-fqdn names
def is_valid_hostname(hostname):
    if len(hostname) > 255:
        return False
    if hostname[-1] == ".":
        hostname = hostname[:-1] # strip exactly one dot from the right, if present
    allowed = re.compile("(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(x) for x in hostname.split("."))


def read_local_trust_config(trust_config='trust_config'):
    '''
    reads a local configuration file containing trusted domains
    and returns them in an array
    '''

    result = []
    if (os.path.isfile(trust_config)):
        f = open(trust_config)
        for line in f:
            line = line.strip()
            if line[0] == '#':
                continue
            try:
                domain, max_depth = line.split(':')
            except:
                print('invalid trust config line detected: %s aborting!' % line)
                sys.exit(8)

            if max_depth in supported_max_depths:
                if is_valid_hostname(domain) and domain not in result:
                    result.append(domain)
                else:
                    print('invalid duplicate domain in trust config file: %s: %s aborting!' % (trust_config, domain))
                    sys.exit(9)
            else:
                print('unsupported max_depth value (%s) used, aborting!' % line)
                sys.exit(10)

        return result
    else:
        print("trust config file %s missing, aborting!" % trust_config)
        sys.exit(11)


def read_local_validation_cache(validation_cache_file=validation_cache_file, trusted_domains=[]):
    '''
    reads the local validation cache and returns all fingerprints in the cache
    for trusted domains

    format of each entry in the cache:
    domain:fingerprint:prooftype:date
    '''

    result = []
    if trusted_domains == []:
        return result
    if (os.path.isfile(validation_cache_file)):
        f = open(validation_cache_file)
        for line in f:
            line = line.strip()
            if line[0] == '#':
                continue
            try:
                domain, fingerprint, prooftype, dt = line.split(':')
            except:
                print('invalid trust cache entry detected: %s aborting!' % line)
                sys.exit(12)

            if domain in trusted_domains:
                result.append(fingerprint)
            else:
                print('ignoring cached entry for untrusted domain %s' % domain)

    else:
        print("Validation cache file not present. It will be created.")
    return result

def get_controller(address='127.0.0.1',port=9151,password=''):
    '''
    connects to a local tor client via the tor ControlPort
    and returns a controller that allows us to easily set specific tor
    configuration options or read tor relay ContactInfo strings for validation
    '''

    try:
        #controller = Controller.from_socket_file(path=torsocketpath)
        controller = Controller.from_port(address=address, port=port)
        controller.authenticate(password=password)
    except Exception as e:
        print('Failed to connect to the tor process, aborting!')
        print(e)
        sys.exit(1)

    if not controller.is_set('UseMicrodescriptors'):
        print('"UseMicrodescriptors 0" is required in your torrc configuration. Exiting.')
        sys.exit(2)

    return controller

def find_validation_candidates(controller, trusted_domains=[],validation_cache=[],accept_all=False):
    '''
    connect to a tor client via controlport and return a dict of all
    not yet validated fingerprints per trusted operators
    format:
    { trusted_domain: { prooftype: [fingerprint, fingerprint, ...]} }

    example content:
    { 'emeraldonion.org' : { 'uri-rsa': ['044600FD968728A6F220D5347AD897F421B757C0', '09DCA3360179C6C8A5A20DDDE1C54662965EF1BA']}}
    '''

    result = {}

    try:
        relays = controller.get_server_descriptors()
    except:
        print('Failed to get relay descriptors via tor\'s ControlPort. Exiting.')
        sys.exit(3)

    ci = TorContactInfoParser()

    for relay in relays:
        if relay.contact:
            fingerprint = relay.fingerprint
            # skip fingerprints we have already successfully validated in the past
            # a future version would check the cache age as well
            if fingerprint in validation_cache:
                continue
            contactstring = relay.contact.decode('utf-8')
            parsed_ci = ci.parse(contactstring)
            if len(parsed_ci) > 0:
                if 'ciissversion' in parsed_ci and 'proof' in parsed_ci and 'url' in parsed_ci:
                    prooftype = parsed_ci['proof']
                    ciurl = parsed_ci['url']
                    if parsed_ci['ciissversion'] in accepted_ciissversions and prooftype in accepted_proof_types:
                        if ciurl.startswith('http://') or ciurl.startswith('https://'):
                            try:
                                domain=urlparse(ciurl).netloc
                            except:
                                print('warning: failed to parse domain %s' % ciurl)
                                domain='error'
                                continue
                        else:
                            domain=ciurl
                        if not is_valid_hostname(domain):
                            domain='error'
                            continue
                        # we can ignore relays that do not claim to be operated by a trusted operator
                        # if we do not accept all
                        if domain not in trusted_domains and not accept_all:
                            continue
                        if domain in result.keys():
                            if prooftype in result[domain].keys():
                                result[domain][prooftype].append(fingerprint)
                            else:
                                result[domain] = { prooftype : [fingerprint] }
                                # mixed proof types are not allowd as per spec but we are not strict here
                                print('warning: %s is using mixed prooftypes %s' % (domain, prooftype))
                        else:
                            result[domain] = {prooftype : [fingerprint]}
    return result


def validate_proofs(candidates, validation_cache_file=validation_cache_file):
    '''
    This function takes the return value of find_validation_candidates()
    and validated them according to their proof type (uri-rsa, dns-rsa)
    and writes properly validated relay fingerprints to the local validation cache
    '''
    dt_utc = datetime.datetime.now(datetime.timezone.utc).date()

    f = open(validation_cache_file, mode='a')
    count = 0

    for domain in candidates.keys():
        for prooftype in candidates[domain].keys():
            if prooftype == 'uri-rsa':
                uri="https://"+domain+"/.well-known/tor-relay/rsa-fingerprint.txt"
                #print("fetching %s...." % uri)
                try:
                    head = requests.head(uri,timeout=20, proxies=proxy, headers=headers)
                except Exception as e:
                    print("HTTP HEAD request failed for %s" % uri)
                    print(e)
                    head = None
                    continue
                if head.status_code == 200:
                    if head.headers['Content-Type'].startswith('text/plain'):
                        try:
                            fullfile = requests.get(uri, proxies=proxy, timeout=10,headers=headers)
                        except:
                            print("HTTP GET request failed for %s" % uri)
                            fullfile = None
                        if fullfile.status_code == 200 and fullfile.headers['Content-Type'].startswith('text/plain'):
                            #check for redirects (not allowed as per spec)
                            if fullfile.url != uri:
                                print('Redirect detected %s vs %s (final)' % (uri, fullfile.url))
                            well_known_content = fullfile.text.upper().split('\n')
                            well_known_content = [i.strip() for i in well_known_content]
                            for fingerprint in candidates[domain][prooftype]:
                                if fingerprint in well_known_content:
                                    # write cache entry
                                    count += 1
                                    f.write('%s:%s:%s:%s\n' % (domain, fingerprint, prooftype, dt_utc))
                                else:
                                    print('FAIL:%s:%s:%s' % (fingerprint, domain, prooftype))
            elif prooftype == 'dns-rsa':
                for fingerprint in candidates[domain][prooftype]:
                    fp_domain = fingerprint+'.'+domain
                    if dns_validate(fp_domain):
                        count += 1
                        f.write('%s:%s:%s:%s\n' % (domain, fingerprint, prooftype, dt_utc))
                    else:
                        print('FAIL:%s:%s:%s' % (fingerprint, domain, prooftype))
    f.close()
    print('successfully validated %s new (not yet validated before) relays' % count)

def dns_validate(domain):
    '''
    performs DNS TXT lookups and verifies the reply
    - is DNSSEC valid and
    - contains only a single TXT record
    - the DNS record contains a hardcoded string as per specification
    https://nusenu.github.io/ContactInfo-Information-Sharing-Specification/#dns-rsa
    '''

    ctx = ub_ctx()
    if (os.path.isfile(libunbound_resolv_file)):
        ctx.resolvconf(libunbound_resolv_file)
    else:
        print('libunbound resolv config file: "%s" is missing, aborting!' % libunbound_resolv_file)
        sys.exit(5)
    if (os.path.isfile(dnssec_DS_file)):
        ctx.add_ta_file(dnssec_DS_file)
    else:
        print('DNSSEC trust anchor file "%s" is missing, aborting!' % dnssec_DS_file)
        sys.exit(6)

    status, result = ctx.resolve(domain, RR_TYPE_TXT, RR_CLASS_IN)
    if status == 0 and result.havedata:
        if len(result.rawdata) == 1 and result.secure:
            # ignore the first byte, it is the TXT length
            if result.data.as_raw_data()[0][1:] == b'we-run-this-tor-relay':
                return True
    return False

def configure_tor(controller, trusted_fingerprints, exitonly=True):
    '''
    takes the list of trusted fingerprints and configures a tor client
    to only use trusted relays in a certain position
    for now we only set exits.
    we refuse to set the configuration if there are less then 40 trusted relays
    '''

    relay_count = len(trusted_fingerprints)

    if relay_count < 41:
        print('Too few trusted relays (%s), aborting!' % relay_count)
        sys.exit(15)

    try:
        controller.set_conf('ExitNodes', trusted_fingerprints)
        print('limited exits to %s relays' % relay_count)
    except Exception as e:
        print('Failed to set ExitNodes tor config to trusted relays')
        print(e)
        sys.exit(20)



trusted_domains = read_local_trust_config()
trusted_fingerprints = read_local_validation_cache(trusted_domains=trusted_domains)
controller = get_controller(address=controller_address,password=controller_password)
r = find_validation_candidates(controller,validation_cache=trusted_fingerprints,trusted_domains=trusted_domains)
validate_proofs(r)

# refresh list with newly validated fingerprints
trusted_fingerprints = read_local_validation_cache(trusted_domains=trusted_domains)
configure_tor(controller, trusted_fingerprints)
