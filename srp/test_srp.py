#!/usr/bin/env python

import unittest
import os.path
import os
import sys
import time
import thread

import srp
import srp._pysrp as _pysrp

test_g_hex = "02"
test_n_hex = '''\
AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4\
A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF60\
95179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF\
747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B907\
8717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB37861\
60279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DB\
FBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73'''


class SRPTests( unittest.TestCase ):

    def doit(self, u_mod, v_mod, g_mod, hash_alg=srp.SHA256, ng_type=srp.NG_1024, n_hex='', g_hex=''):
        User                           = u_mod.User
        Verifier                       = v_mod.Verifier
        create_salted_verification_key = g_mod.create_salted_verification_key

        username = 'test1'
        password = 'M1'

        _s, _v = create_salted_verification_key( username, password, hash_alg, ng_type, n_hex, g_hex )

        usr      = User( username, password, hash_alg, ng_type, n_hex, g_hex, True )
        uname, A = usr.start_authentication()
    
        # username, A => server
        svr      = Verifier( uname, _s, _v, A, hash_alg, ng_type, n_hex, g_hex, True )
        #s,B      = svr.get_challenge()
        s = '58e776c47fe49a76a018fcbe52a0044bb61aba967e8d4be1d7414a0462fc232f'
        B = '5fbc3af608fed6c64978771fc9e3a36e6ae9e6e0433dc1da2819095dd2c5e9390b465f12cf25164b645abaf5bb306dfe6cd2db8e9f900a2519c008fff51771ff95b50e007fb3f1b1eb4043ea0bddac889ba6aa6c294e56b6ce5f52739010c4da3c6fd7f53f6cd38cc1451224b4e4f5cd4bfbcd13f012370d0a4c9477a7ad03b5'
        
        # s,B => client
        M        = usr.process_challenge( s, B )
        print M

        # M => server
        #HAMK     = svr.verify_session( M )
        HAMK = "bfb21cbb57db79eab3767188209139e6bb60ffb2e45ddef1cf22b8040e09856e"
        # HAMK => client
        usr.verify_session( HAMK )

        self.assertTrue( svr.authenticated() and usr.authenticated() )

    def test_pure_python_defaults(self):
        self.doit( _pysrp, _pysrp, _pysrp )

print '*'*60
print '*'
print '* Run Tests'
print '*'
suite = unittest.TestLoader().loadTestsFromTestCase(SRPTests)
unittest.TextTestRunner(verbosity=1).run(suite)

print '*'*60
