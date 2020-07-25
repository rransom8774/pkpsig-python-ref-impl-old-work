
import pkpsig.keys, pkpsig.signatures

pkblob, skblob = pkpsig.keys.generate_keypair()

sk = pkpsig.keys.SecretKey().unpack(skblob)
pk = pkpsig.keys.PublicKey().unpack(pkblob)

ivs_sign, ivs_verify = dict(), dict()

signull = pkpsig.signatures.generate_signature(sk, b'', ivs=ivs_sign)
verified = pkpsig.signatures.verify_signature(pk, signull, b'', ivs=ivs_verify)

print('ivs_sign = %r' % ivs_sign)
print('ivs_verify = %r' % ivs_verify)

print('verified = %r' % verified)

