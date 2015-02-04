# -*- Mode: Python; py-indent-offset: 4; coding: utf-8 -*-:
# vim: tabstop=4 shiftwidth=4 expandtab

## Copyright (C) 2014, University of Zurich and ETH Zurich
## Copyright (C) 2014, Claudio Luck <cluck@ini.uzh.ch>

## Licensed under the terms of the MIT License, see LICENSE file.

from __future__ import print_function

import sys
import os
import time
import logging
import codecs
import getpass

import ldap
import ldap.sasl
from ldap.controls import RequestControlTuples


__version__ = '1.0a2'
__author__ = 'Claudio Luck'
__author_email__ = 'claudio.luck@gmail.com'


TOKENS = (
    'HOST',
    'PORT',
    'URI',
    'BASE',
    'BINDDN',
    'BINDPW',
    'USERNAME',
    'X_BINDPW_FILE',
    'DEREF',
    'NETWORK_TIMEOUT',
    'REFERRALS',
    'SIZELIMIT',
    'TIMELIMIT',
    'TIMEOUT',
    'SASL_REALM',
    'SASL_AUTHCID',
    'SASL_AUTHZID',
    'SASL_SECPROPS',
    'GSSAPI_SIGN',
    'GSSAPI_ENCRYPT',
    'GSSAPI_ALLOW_REMOTE_PRINCIPAL',
    'TLS_CACERT',
    'TLS_CACERTDIR',
    'TLS_CERT',
    'TLS_KEY',
    'TLS_CIPHER_SUITE',
    'TLS_RANDFILE',
    'TLS_REQCERT',
    'TLS_CRLCHECK',
    'TLS_CRLFILE',
    'SASL_MECH',
)

USER_VALUES = (
    'BINDDN',
    'BINDPW',
    'X_BINDPW_FILE',
    'SASL_MECH',
    'SASL_REALM',
    'SASL_AUTHCID',
    'SASL_AUTHZID',
    'TLS_CERT',
    'TLS_KEY',
)

UNSUPPORTED = (
    'SASL_REALM',  # ValueError: unknown option 24833
)

class LdapRc( object ):

    log = logging.getLogger('ldaprc')
    prefix = '/etc/openldap'

    def __init__(self, logger=None, prefix=None):
        if logger:
            self.log = logging.getLogger(logger)
        if prefix:
            self.prefix = prefix
        self.tokseq = []

    def initialize(self, uri=None, *args, **kwargs):
        assert uri is None, 'uri MUST be None when using LdapRc.initialize()'
        config = {}
        tokseq = []
        if 'LDAPNOINIT' not in os.environ:
            config = {}   # TODO: add defaults here
        rclist = [ (0, os.path.join(self.prefix, 'ldap.conf')) ]
        homedir = os.path.expanduser('~')
        if homedir != '~':
            rclist += (
                    (1, os.path.join(homedir, 'ldaprc')),
                    (1, os.path.join(homedir, '.ldaprc')),
                )
        rclist += ( (1, 'ldaprc'), )
        if 'LDAPCONF' in os.environ:
            rclist += ( (0, os.environ['LDAPCONF']), )
        if 'LDAPRC' in os.environ:
            if homedir != '~':
                rclist += (
                        (1, os.path.join(homedir, os.environ['LDAPRC'])),
                        (1, os.path.join(homedir, '.' + os.environ['LDAPRC'])),
                    )
            rclist += ( (1, os.environ['LDAPRC']), )
        #
        for rcx in rclist:
            rcuser, rcpath = bool(rcx[0]), os.path.expanduser(rcx[1])
            if os.access(rcpath, os.R_OK) and not os.path.isdir(rcpath):
                cf = self._parse(config, rcpath, rcuser, tokseq)
        #
        if 'X_BINDPW_FILE' in config:
            if not os.path.isabs(config['X_BINDPW_FILE']):
                bindpf = os.path.expanduser( os.path.join( os.path.dirname(rcpath), config['X_BINDPW_FILE'] ))
            else:
                bindpf = config['X_BINDPW_FILE']
            if os.access(bindpf, os.R_OK) and not os.path.isdir(bindpf):
                with codecs.open(bindpf, 'r', 'utf-8') as pwf:
                    config['BINDPW'] = pwf.read()
                del config['X_BINDPW_FILE']
        for tok in TOKENS:
            earg = os.environ.get('LDAP' + tok)
            if earg is not None:
                config[tok] = earg
        self.ldaprc = config
        self.tokseq = tokseq
        lobj = ldap.initialize(config.get('URI', uri), *args, **kwargs)
        return lobj

    def set_option(self, conn, opt, arg):
        conn.set_option(opt, arg)
        v = conn.get_option(opt)
        if v != arg:
            print('OK {0}({1})={2} ({3})'.format(ldap.OPT_NAMES_DICT[opt], opt, v, arg))
        else:
            print('OK {0}({1})={2}'.format(ldap.OPT_NAMES_DICT[opt], opt, v))

    def bind_s(self, lobj, who=None, auth=None, cred=None, serverctrls=None, clientctrls=None,
            method=ldap.AUTH_SIMPLE, sasl_flags=ldap.SASL_QUIET
        ):
        if who is None:
            who = self.ldaprc.get('BINDDN')
            if who is None:
                who = getpass.getuser()
                who = 'cn={0},{1}'.format(ldap.dn.escape_dn_chars(who),
                                          self.ldaprc['BASE'])
        for tok in self.tokseq:
            try:
                fn = getattr(self, 'rc_' + tok)
            except AttributeError as e:
                print(type(e).__name__, str(e))
                continue
            except BaseException as e:
                print(tok, self.ldaprc[tok], type(e).__name__, str(e))
                raise
            fn(lobj, self.ldaprc[tok])
            #v = self.ldaprc[tok] if tok != 'BINDPW' else '*'*len(self.ldaprc[tok])
            #print('OK {0}={1}'.format(tok, v))
        tls = lobj.get_option(ldap.OPT_X_TLS_REQUIRE_CERT) in (
                ldap.OPT_X_TLS_HARD, ldap.OPT_X_TLS_TRY, ldap.OPT_X_TLS_ALLOW
        )
        if tls:
            con.start_tls_s()
        gss = False
        if ldap.SASL_AVAIL:
            gss = lobj.get_option(ldap.OPT_X_SASL_MECH) == 'GSSAPI'
        if gss:
            if auth is None:
                auth = ldap.sasl.gssapi()
            return lobj.sasl_interactive_bind_s(who, auth,
                RequestControlTuples(serverctrls),
                RequestControlTuples(clientctrls), sasl_flags
            )
        cred = self.ldaprc.get('BINDPW') or ''
        msgid = lobj.bind(who, cred)
        return lobj.result(msgid, all=1, timeout=lobj.timeout)

    def _parse(self, config, rcf, rcuser, tokseq):
        with codecs.open(rcf, 'r', 'utf-8') as rcfh:
            for line in rcfh:
                line = line.rstrip()
                if not line or line[0] == '#':
                    continue
                tok, arg = line.split(' ', 1)
                tok = tok.upper()
                if not rcuser and tok in USER_VALUES:
                    continue
                if tok not in TOKENS:
                    continue
                if tok.startswith('SASL_') and not ldap.SASL_AVAIL:
                    continue
                if tok in UNSUPPORTED:
                    print('Not supported option: {0}'.format(tok))
                    continue
                if tok not in tokseq:
                    tokseq.append(tok)
                arg = arg.lstrip()
                config[tok] = arg
        return config

    def rc_URI(self, conn, arg):
        self.set_option(conn, ldap.OPT_URI, arg)

    def rc_HOST(self, conn, arg):
        raise NotImplemented()

    def rc_PORT(self, conn, arg):
        raise NotImplemented()

    def rc_BASE(self, conn, arg):
        pass

    def rc_BINDDN(self, conn, arg):
        pass

    def rc_BINDPW(self, conn, arg):
        pass

    def rc_DEREF(self, conn, arg):
        arg = arg.lower()
        if arg == 'never':
            self.set_option(conn, ldap.DEREF_NEVER)
        elif arg == 'searching':
            self.set_option(conn, ldap.DEREF_SEARCHING)
        elif arg == 'finding':
            self.set_option(conn, ldap.DEREF_FINDING)
        elif arg == 'always':
            self.set_option(conn, ldap.DEREF_ALWAYS)

    def rc_NETWORK_TIMEOUT(self, conn, arg):
        conn.network_timeout = int(arg)

    def rc_REFERRALS(self, conn, arg):
        arg = arg.lower()
        if arg == ('true', 'on', 'yes'):
            self.set_option(conn, ldap.OPT_REFERRALS, True)
        elif arg in ('false', 'off', 'no'):
            self.set_option(conn, ldap.OPT_REFERRALS, False)
        
    def rc_SIZELIMIT(self, conn, arg):
        conn.sizelimit = int(arg) 

    def rc_TIMELIMIT(self, conn, arg):
        conn.timelimit = int(arg) 

    def rc_TIMEOUT(self, conn, arg):
        conn.timeout = int(arg) 

    # GSSAPI

    def rc_GSSAPI_SIGN(self, conn, arg):
        raise NotImplemented()

    def rc_GSSAPI_ENCRYPT(self, conn, arg):
        raise NotImplemented()

    def rc_GSSAPI_ALLOW_REMOTE_PRINCIPAL(self, conn, arg):
        raise NotImplemented()

    # TLS
    
    def rc_TLS_CACERT(self, conn, arg):
        self.set_option(conn, ldap.OPT_X_TLS_CACERTFILE, arg)

    def rc_TLS_CACERTDIR(self, conn, arg):
        # Ignored on GnuTLS
        self.set_option(conn, ldap.OPT_X_TLS_CACERTDIR, arg)
        
    def rc_TLS_CERT(self, conn, arg):
        self.set_option(conn, ldap.OPT_X_TLS_CERTFILE, arg)

    def rc_TLS_KEY(self, conn, arg):
        self.set_option(conn, ldap.OPT_X_TLS_KEYFILE, arg)

    def rc_TLS_CIPHER_SUITE(self, conn, arg):
        self.set_option(conn, ldap.OPT_X_TLS_CIPHER_SUITE, arg)

    def rc_TLS_RAND_FILE(self, conn, arg):
        self.set_option(conn, ldap.OPT_X_TLS_RANDOM_FILE, arg)

    def rc_TLS_REQCERT(self, conn, arg):
        arg = arg.lower()
        if arg == 'hard':
            self.set_option(conn, ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_HARD)
        elif arg == 'demand':
            self.set_option(conn, ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_DEMAND)
        elif arg == 'try':
            self.set_option(conn, ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_TRY)
        elif arg == 'allow':
            self.set_option(conn, ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_ALLOW)
        elif arg == 'never':
            self.set_option(conn, ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)

    def rc_TLS_CRLCHECK(self, conn, arg):
        raise NotImplemented()

    def rc_TLS_CRLFILE(self, conn, arg):
        raise NotImplemented()

    # SASL
 
    def rc_SASL_SECPROPS(self, conn, arg):
        print('SASL_SECPROPS='+arg)
        return
        self.set_option(conn, ldap.OPT_X_SASL_SECPROPS, arg)

    def rc_SASL_REALM(self, conn, arg):
        self.set_option(conn, ldap.OPT_X_SASL_REALM, arg)

    def rc_SASL_MECH(self, conn, arg):
        pass

    def _disabled_rc_SASL_MECH(self, conn, arg):
        arg = arg
        # SASL_AUTHZID
        if arg == 'EXTERNAL':  # PKI
            # TLS_CERT / TLS_KEY
            pass
        elif arg == 'DIGEST-MD5':
            # SASL_AUTHCID
            pass
        elif arg == 'GSSAPI':
            # SASL_AUTHCID / SASL_REALM
            pass
        else:
            pass


if __name__ == "__main__":

    pass
    
