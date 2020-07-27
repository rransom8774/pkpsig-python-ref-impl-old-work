
# Authors: Robert Ransom

# This software is released to the public domain.

# To the extent permitted by law, this software is provided WITHOUT ANY
# WARRANTY WHATSOEVER.

from . import common

def check_sorted_perm(l, orig):
    for i in range(len(l)):
        if l[i] != i:
            raise common.DataError("Invalid permutation %r" % orig)
        pass
    pass

def check_perm(perm, orig):
    l = list(perm)
    l.sort()
    check_sorted_perm(l, orig)
    pass

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

def squish(perm):
    l = list(perm)
    check_perm(l, perm)
    for i in range(len(l)):
        for j in range(i+1, len(l)):
            if l[j] > l[i]:
                l[j] -= 1
                pass
            pass
        pass
    assert(l[len(l)-1] == 0)
    return l[:len(l)-1]

def unsquish(perm_squished):
    l = list(perm_squished)
    l.append(0)
    for i in reversed(range(len(l))):
        for j in range(i+1, len(l)):
            if l[j] >= l[i]:
                l[j] += 1
                pass
            pass
        pass
    return l

