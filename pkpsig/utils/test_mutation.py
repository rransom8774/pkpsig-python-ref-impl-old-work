
# Authors: Robert Ransom

# This software is released to the public domain.

# To the extent permitted by law, this software is provided WITHOUT ANY
# WARRANTY WHATSOEVER.

import sys

import pkpsig.keys, pkpsig.signatures

NOISY = True

pkblob, skblob = pkpsig.keys.generate_keypair()

#pkblob = b'\xec\nX\xa9k\x19\xfa\x94\xe5Qh\x19\xbb\xda\x08\xec\xe1\xab\x9a\xa5\x0e/\xe9\xde\xeb"\x0b\x87\xa0\xe3W\xc4)\x9a\x0b\xcd\xfeS\xb92\xd9\xc5\xd23u\x84|\xbe\xd9&\xbc@'
#skblob = b'\xec\nX\xa9k\x19\xfa\x94\xe5Qh\x19\xbb\xda\x08\xec\xe1\x13\xe4~\xcf\x175\x04\xbdh\x8e;\x7f7\x19\xed\xeeE\xef\r0\xffv\xe4X}:z#\x10#4R\x91\x1e\xc2<\x01Q\xba\xa2\xe6vH#%\x05n\x02\xe3\xb9\xf4p\x08\xa3\x99\xd3\xe2\xd3\xfa\xbb\x05\xcd\xaf\xfaM3\x90\x839\xf2gp'

sk = pkpsig.keys.SecretKey().unpack(skblob)
pk = pkpsig.keys.PublicKey().unpack(pkblob)

def frob_byte(sig, bytepos):
    buf = bytearray(sig)
    buf[bytepos] = (buf[bytepos] + 1) % 256
    return bytes(buf)

exceptions = dict()

def verify_noexcept(pk, sig, msg):
    try:
        return pkpsig.signatures.verify_signature(pk, sig, msg)
    except:
        ei = sys.exc_info()
        exceptions[(pk, sig, msg)] = ei
        print('Exception %r' % ei[0])
        return False
    assert(not "can't happen")
    pass

bogons = dict()

def report(testname, testsub, result, expected):
    if result != expected:
        bogons[(testname, testsub)] = (result, expected)
        pass
    if NOISY or (result != expected):
        print('  %s: %r (expected %r)' % (testsub, result, expected))
        pass
    pass

def test_loop(testname, pk, sig, msg, is_valid):
    print('%s:' % testname)
    report(testname, 'unmodified', verify_noexcept(pk, sig, msg), is_valid)
    for i in range(len(sig)):
        frobbed = frob_byte(sig, i)
        report(testname, 'frobbed byte %d' % i, verify_noexcept(pk, frobbed, msg), False)
        pass
    pass

signull = pkpsig.signatures.generate_signature(sk, b'')
sigalpha = pkpsig.signatures.generate_signature(sk, b'abcdefghijklmnopqrstuvwxyz')

test_loop('null message', pk, signull, b'', True)
test_loop('lowercase-alphabet message', pk, sigalpha, b'abcdefghijklmnopqrstuvwxyz', True)

test_loop('null-message sig verified for lowercase-alphabet message', pk, signull, b'abcdefghijklmnopqrstuvwxyz', False)
test_loop('lowercase-alphabet message sig verified for null message', pk, sigalpha, b'', False)

print('bogons = %r' % bogons)

