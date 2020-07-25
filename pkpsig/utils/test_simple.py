
import pkpsig.keys, pkpsig.signatures

#pkblob, skblob = pkpsig.keys.generate_keypair()

pkblob = b'cN\x83-\x878k5\x9e\xca\xe7\xb7\xb3\xcd@\xabX\xd5\xa3\xb2\t=\xdag\xb5\xe5\x82\x1b\xdav\x8c\xf6\xb4\xe4F\x1d\x89\xd6LZ\xbd\xf4\xa8\xa8\xda_\x82\xf3\x99\x04\x00N'
skblob = b'cN\x83-\x878k5\x9e\xca\xe7\xb7\xb3\xcd@\xabX\xc1\x02\xc5\xb1\xadM\xf5Ig\xa4\xe2\xc5e\x01\xa8^\x0f\xcc9\xc6\x9fb:\x95\xd5"\x0e\xf94\xe1\x05]\x89\x10\x02\xdb1\x18\xdb\xba\x0el\xb1\x14\xa8|Q\xf6F\xea\xc7H*\xe4\x95\xd8\xf4f\xcd\x00\t\xd2\xa2\x03BF\xd1uoW,F'

sk = pkpsig.keys.SecretKey().unpack(skblob)
pk = pkpsig.keys.PublicKey().unpack(pkblob)

ivs_sign, ivs_verify = dict(), dict()

signull = pkpsig.signatures.generate_signature(sk, b'', ivs=ivs_sign)
verified = pkpsig.signatures.verify_signature(pk, signull, b'', ivs=ivs_verify)

print('ivs_sign = %r' % ivs_sign)
print('ivs_verify = %r' % ivs_verify)

print('verified = %r' % verified)

