# -*- Mode: Python; py-indent-offset: 4; coding: utf-8 -*-:
# vim: tabstop=4 shiftwidth=4 expandtab

## Copyright (C) 2014, University of Zurich and ETH Zurich
## Copyright (C) 2014, Claudio Luck <cluck@ini.uzh.ch>

## Licensed under the terms of the MIT License, see LICENSE file.


import sys
import os

from pprint import pprint

import ldap
from ldaprc import LdapRc

def main():

    print "api info:", ldap.get_option(ldap.OPT_API_INFO)
    #ldap.set_option(ldap.OPT_DEBUG_LEVEL, 7)
    print "debug level:",ldap.get_option(ldap.OPT_DEBUG_LEVEL)

    rc = LdapRc()
    print(repr(rc))

    lobj = rc.initialize()
    print(repr(lobj))

    try:
        x = rc.bind_s(lobj)
    except ValueError as e:
        raise

    print('BASE = ' + rc.ldaprc['BASE'])
    ldap.set_option(ldap.OPT_DEBUG_LEVEL, 0)
    y = lobj.search_s(rc.ldaprc['BASE'],
        ldap.SCOPE_SUBTREE, '(objectClass=*)', ['cn'])
    pprint(y)

if __name__ == "__main__":
    os.environ['LDAPRC'] = 'ldaprc.test'
    main()
