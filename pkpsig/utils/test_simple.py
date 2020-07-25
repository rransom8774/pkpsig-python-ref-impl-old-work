
import pkpsig.keys, pkpsig.signatures

pkblob, skblob = pkpsig.keys.generate_keypair()

sk = pkpsig.keys.SecretKey().unpack(skblob)
pk = pkpsig.keys.PublicKey().unpack(pkblob)

signull = pkpsig.signatures.generate_signature(sk, b'')
assert(pkpsig.signatures.verify_signature(pk, signull, b''))

