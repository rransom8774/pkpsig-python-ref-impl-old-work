
# Authors: Robert Ransom

# This software is released to the public domain.

from . import common

def compose_inv(pi, sigma):
    "compose_inv(pi, sigma) -> pi \compose sigma^(-1)"
    assert(len(pi) == len(sigma))
    l = list(zip(sigma, pi))
    l.sort()
    for i in range(len(l)):
        if l[i][0] != i:
            raise common.DataError("Invalid permutation %r" % sigma)
        pass
    return [l[i][1] for i in range(len(l))]

def apply_inv(v, sigma):
    "apply_inv(v, sigma) -> v_(sigma^(-1))"
    # Same implementation as compose_inv in Python, but v can have
    # larger elements, so a constant-time implementation may pack the
    # array elements differently for sorting.
    assert(len(v) == len(sigma))
    l = list(zip(sigma, v))
    l.sort()
    for i in range(len(l)):
        if l[i][0] != i:
            raise common.DataError("Invalid permutation %r" % sigma)
        pass
    return [l[i][1] for i in range(len(l))]

def inverse(pi):
    "inverse(pi) -> pi^(-1)"
    return compose_inv(range(len(pi)), pi)

def inverse_and_apply_inv(v, sigma):
    "apply_inv(v, sigma) -> (sigma^(-1), v_(sigma^(-1)))"
    assert(len(v) == len(sigma))
    l = list(zip(sigma, range(len(sigma)), v))
    l.sort()
    for i in range(len(l)):
        if l[i][0] != i:
            raise common.DataError("Invalid permutation %r" % sigma)
        pass
    return ([l[i][1] for i in range(len(l))], [l[i][2] for i in range(len(l))])

