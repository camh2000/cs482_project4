q = 31
p = 3
halfq = q*0.5
# print ("HalfQ = ", halfq, '\n')
halfq = int(halfq)
N = 23
R.<x> = PolynomialRing(GF(q), 'x')
x1 = x^N - 1
originalx1 = x1

###
### KEY generation; we start with f(x) and g(x); they are calculated from F(x) and G(x) respectively
###
print ('\n++++++++++ KEY GENERATION BEGINS ++++++++++')
fx_str = '3*x^4 - 3*x^3 + 3*x^2 - 3*x + 1'
fx = R(fx_str)
print ('PRIVATE KEY fx = ', fx_str)

#
x2 = fx
#
#
# print ('x1 = ', x1)
# print ('x2 = ', x2)
t1 = 0
t2 = 1
s1 = 1
s2 = 0
#
# The following is to calculate polynmial xgcd and its answer is NOT complete until the integer xgcd is integrated
#
while x2.degree() >= 0:
    q, newx   =  x1.quo_rem (x2)
    x1 = x2
    x2 = newx
    # print ('q = ', q)
    # print ('x = ', newx, '\n')
    newt = t1 - t2*q
    news = s1 - s2*q
    t1 = t2
    t2 = newt
    s1 = s2
    s2 = news

# print ('s1 = ', s1)
# print ('s2 = ', s2)
# print ('t1 = ', t1)
# print ('t2 = ', t2)

#
# The following calculate integer xgcd
#
# print ('x1 = ', x1)
x1inverse = inverse_mod(x1, q)

#
# The integer xgcd is integrated below
#
fqx = t1 * x1inverse
print ('\nfqx (needs to manually mods 31)  = ', fqx)

#
gx_str = '3x^9 + 3x^3 - 3x'
gx = R(gx_str)
print ('\ngx = ', gx_str)

hx = fqx * gx

#
# print ('Pre-public key (BEFORE reduction) = ', hx)
lastq, lastrem = hx.quo_rem (originalx1)
#
# we should perform mods q, but sage does not do that; Have to manually do this
#
print ('\nPublic key (before mods 31; needs to manually mods 31 by you) = ', lastrem)

##############################################
########### NTRU ENCRYPTION ##################
##############################################
###
### PLAINTEXT
###
print ('\n++++++++++ ENCRYPTION BEGINS ++++++++++')
mx_str = 'x^13 - x^11 + x^9 - 1'
mx = R(mx_str)
print ('Plaintext m(x) = ', mx_str)

#
# Random polynomial for encryption
#
rx_str = 'x^18 + x^15 + x^7 - x^3'
rx = R (rx_str)
print ('Random r(x) = ', rx_str)

cx = rx * lastrem + mx
lastq2, lastrem2 = cx.quo_rem(originalx1)
print ('\nCiphertext (needs to manually mods 31) = ', lastrem2)

##############################################
########### NTRU DECRYPTION ##################
##############################################
print ('\n++++++++++ DECRYPTION BEGINS ++++++++++')
ax = fx * cx
lastq3, lastrem3 = ax.quo_rem(originalx1)
print ('STEP 1: cleartext ax (needs to manually mods 31) = ', lastrem3)

print ('\nSTEP 2: needs to manually calculate ax mods p')
