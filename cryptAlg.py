#Nishaant Goswamy


import math as m

def primeCheck(num):
    if num > 1:
        # lopp throught all divisor from 2 to n / 2
        for i in range(2, (num//2) + 1):
            if (num % i) == 0:
                print(num, "is not a prime number")
                return False

        print(num, "is a prime number", )
        return True
    else:
        print(num, "is not a prime number")
        return False

def Totient(p, q):
    return (p - 1) * (q - 1)

def GCD(x, y):
    while y != 0:
        x, y = y, x % y
    return x

def Coprime(n):
    for i in range(2, n):
        if GCD(i, n) == 1:  # stops at the smallest e value
            return i

# Extended Euclidean algorithms that takes two coprime nums and finds and find inverse mode
def Inverse_Mod(e, m):
    m0 = m
    y = 0
    x = 1

    if (m == 1):
        return 0

    while (e > 1):
        q = int(e / m)  # q is quotient

        temp = m

        m = e % m
        e = temp
        temp = y

        # Update x and y
        y = x - q * y
        x = temp

    # Make x positive
    if (x < 0): x = x + m0

    return x


def primeFactors(n):
    prime_list = []

    while n % 2 == 0:
        prime_list.append(2)
        n = n / 2
    # increment in odd i values
    for i in range(3, int(m.sqrt(n)) + 1, 2):

        # if n is divisible by i, save i to list
        while n % i == 0:
            prime_list.append(i)
            n = n / i

    # Condition if n is a prime then save it to list
    if n > 2:
        prime_list.append(int(n))
    return set(prime_list)


def Generator(p_1, p):
        prime_set = primeFactors(p_1)

        for g in range(2, p_1):  # generator is 1<g< p-1
            count = 0
            for i in prime_set:  # cycles through all prime factor to check for generator
                if Square_And_Multiply(g, (p_1 // i), p) != 1:
                    count += 1
                    if count == len(prime_set):  # if g value works with all prime factors then its a generator.
                        return g



def Square_And_Multiply(u, m, p):

    # A:=(u^m) mod p
    #intial setup
    A = 1
    b = m % 2
    if b == 1:
        A = (A*u) % p

    while m != 1:
        m = (m - b)//2    # integer quotient
        b = m % 2
        u = (u*u)%p
        if b == 1:
            A = (A * u) % p
    return A