#Nishaant Goswamy

from CompressDecompress import CompressEncodedText, DecompressEncodedText,Letter_Decoding
import cryptAlg as crypt

print("This is RSA Signature")
p = int(input("Enter a prime value for p: "))
q = int(input("Enter a prime value for q: "))

if crypt.primeCheck(p) == True and crypt.primeCheck(q) == True:
    print("Success P and Q are prime numbers")

    m = p * q
    totientM = crypt.Totient(p, q)
    print(" m = ", m)
    print("ϕ(m) = ", totientM)

    e_key = crypt.Coprime(totientM)
    print("e value coprime to ϕ(m): ", e_key)  # smallest e value coprime to ϕ(n):

    d_key = crypt.Inverse_Mod(e_key, totientM)
    print("d value [de ≡ 1 (mod ϕ(m)))]: ", d_key)  # The d value for

else:
    print("P and Q not Prime. Function exited")
    quit()

r = int(input("Enter a prime value for r: "))
s = int(input("Enter a prime value for s: "))

if crypt.primeCheck(r) == True and crypt.primeCheck(s) == True:
    print("Success R and S are prime numbers")

    n = r * s
    totientN = crypt.Totient(r, s)
    print(" n = ", n)
    print("ϕ(n) = ", totientN)

    h_key = crypt.Coprime(totientN)
    print("h value coprime to ϕ(n): ", h_key)  # smallest e value coprime to ϕ(n):

    g_key = crypt.Inverse_Mod(h_key, totientN)
    print("g value [gh ≡ 1 (mod ϕ(n)))]: ", g_key)  # The d value for

else:
    print("R and S not Prime. Function exited")
    quit()

# msg_num = int(input("Enter a msg num (should be less than m): "))

msg = (input("Enter the message string: "))
MsgNumList, size = CompressEncodedText(msg)

signedMsgList = []
encryptedMsgList = []

decrypetedMsgList = []
verifiedMsgList = []

for msg_num in MsgNumList:

    msg_num = int(msg_num)

    print("***Signing & Encrypting***")

    print("Msg num:", msg_num)
    if msg_num > m:
        print("Msg_Num bigger than m. Aborted")
        quit()
    x = crypt.Square_And_Multiply(msg_num, d_key, m)  # signing the message with d (private key)
    signedMsgList.append(str(x).zfill(size))
    print("Signed Message x =(num**d)%m: ", x)

    if x > n:
        print("x bigger than n. Aborted")
        quit()
    y = crypt.Square_And_Multiply(x, h_key, n)  # encrypting the message with h (public key)
    encryptedMsgList.append(str(y).zfill(size))
    print("Encrypted Message y =(x**h_key)% n:", y)

    if y > n:
        print("y bigger than n. Aborted")
        quit()
    print("***Decrypting & Verifying***")
    z = crypt.Square_And_Multiply(y, g_key, n)  # decrypt with private key g
    decrypetedMsgList.append(str(z).zfill(size))
    print("Decrypted Message  z =(y**g_key)%n: ", z)

    if z > m:
        print("z bigger than m. Aborted")
        quit()
    u = crypt.Square_And_Multiply(z, e_key, m)  # verify with public key e
    verifiedMsgList.append(str(u).zfill(size))
    print("Verifying Message u =(z**e_key)%m: ", u)

    if msg_num == u:
        print("Success!! The message sent and received are the same\n")
    else:
        print("Error message received is not the same\n")
        quit()

print("Signed Message:", signedMsgList)
print("Encrypted Message:", encryptedMsgList)

print("Decrypted Message:", decrypetedMsgList)
print("Verified Message:", verifiedMsgList)
verifyEncodedMsg  = int(''.join([str(x) for x in verifiedMsgList]))
print("Compressed Encoded Message:", verifyEncodedMsg )

decompress_num, decompress_numList, decoded_text = DecompressEncodedText(MsgNumList)
print("Decompressed Encoded Message:", decompress_num)
print("Decompressed Encoded Message:", decompress_numList)
print("Decrypted Decompressed Set:", end=" ")
for i in decompress_numList:
    print(i + ":" + Letter_Decoding(int(i)), end=", ")
print("\nDecoded Text:", decoded_text)

if msg == decoded_text:
    print("\nSuccess!! Original message match Decrypted Message: " + decoded_text, "==", msg)
