import timeit
from tinyec import registry
import secrets
curve = registry.get_curve('secp192r1')
P=curve.g
print(len(str(P.x)))


code_to_test = """
from tinyec import registry
import secrets
curve = registry.get_curve('secp192r1')
xs = secrets.randbelow(curve.field.n)
tag_identifier=secrets.randbelow((curve.field.n))
P=curve.g
Ps = xs * curve.g
K=secrets.randbelow(curve.field.n)
IDS=secrets.randbelow(curve.field.n)
xt=tag_identifier*P
"""
#elapsed_time=timeit.timeit(code_to_test,number=1000)/1000
#print(elapsed_time)
