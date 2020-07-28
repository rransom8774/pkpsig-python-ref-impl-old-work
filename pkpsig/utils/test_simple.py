
# Authors: Robert Ransom

# This software is released to the public domain.

# To the extent permitted by law, this software is provided WITHOUT ANY
# WARRANTY WHATSOEVER.

import pkpsig.keys, pkpsig.signatures

#pkblob, skblob = pkpsig.keys.generate_keypair()

pkblob = b'\xec\nX\xa9k\x19\xfa\x94\xe5Qh\x19\xbb\xda\x08\xec\xe1\xab\x9a\xa5\x0e/\xe9\xde\xeb"\x0b\x87\xa0\xe3W\xc4)\x9a\x0b\xcd\xfeS\xb92\xd9\xc5\xd23u\x84|\xbe\xd9&\xbc@'
skblob = b'\xec\nX\xa9k\x19\xfa\x94\xe5Qh\x19\xbb\xda\x08\xec\xe1\x13\xe4~\xcf\x175\x04\xbdh\x8e;\x7f7\x19\xed\xeeE\xef\r0\xffv\xe4X}:z#\x10#4R\x91\x1e\xc2<\x01Q\xba\xa2\xe6vH#%\x05n\x02\xe3\xb9\xf4p\x08\xa3\x99\xd3\xe2\xd3\xfa\xbb\x05\xcd\xaf\xfaM3\x90\x839\xf2gp'

sk = pkpsig.keys.SecretKey().unpack(skblob)
pk = pkpsig.keys.PublicKey().unpack(pkblob)

ivs_sign, ivs_verify = dict(), dict()

signull = pkpsig.signatures.generate_signature(sk, b'', ivs=ivs_sign)
verified = pkpsig.signatures.verify_signature(pk, signull, b'', ivs=ivs_verify)

print('ivs_sign = %r' % ivs_sign)
print('ivs_verify = %r' % ivs_verify)

print('verified = %r' % verified)

