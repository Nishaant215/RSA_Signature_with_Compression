#Nishaant Goswamy

import string as s
import cryptAlg as crypt

def Text_Encoding(text):
    alpha_numeric_dict = dict(zip(s.ascii_lowercase, [str(i).zfill(2) for i in range(0, 26)]))

    encoded_text = ""
    for letter in text:
        encoded_text += alpha_numeric_dict[letter]
        print(letter + ":" + alpha_numeric_dict[letter], end=" ")

    encode_numlist = [encoded_text[i:i + 2] for i in range(0, len(encoded_text), 2)]
    print("\nEncoded Text List:", encode_numlist)
    print("Encoded Text:", encoded_text, ", len:", len(encoded_text))
    return encode_numlist


def NumCompression(encode_numlist):
    exp = len(encode_numlist) - 1
    compressed_num = 0
    for num in encode_numlist:
        compressed_num += int(num) * (26 ** exp)
        # print("Num="+num+" exp:",exp,"=>compress_num", compressed_num)
        exp -= 1

    compressed_num_len = len(str(compressed_num))

    print("Compressed Encoding: ", compressed_num, ", len:", compressed_num_len)

    if crypt.primeCheck(compressed_num_len):
        print("number of digits in compress number is a prime. Add letter x for padding at the end.")
        quit()

    return compressed_num


def SplitCompressNum(num):
    num = str(num)
    num_len = len(num)

    size = int(input("Enter size of each chunk: "))
    compress_encoded_list = [num[i:i + size] for i in range(0, num_len, size)]
    print("Compressed Encoding List:", compress_encoded_list, "\n")
    return compress_encoded_list, size


def CompressEncodedText(text):
    encoded_num_list = Text_Encoding(text)
    compressed_num = NumCompression(encoded_num_list)
    compressed_num_list, digits_size = SplitCompressNum(compressed_num)
    return compressed_num_list, digits_size


def Letter_Decoding(val):
    alpha_numeric_dict = dict(zip([i for i in range(0, 26)], s.ascii_lowercase))
    return alpha_numeric_dict[val]


def DecompressEncodedText(compressNumList):
    decoded_text = ""
    decompress_numList = []

    compressNum = int(''.join([str(x) for x in compressNumList]))

    while compressNum >= 26:
        letterVal = int(compressNum % 26)
        decoded_text += Letter_Decoding(letterVal)
        decompress_numList.append(letterVal)

        compressNum = (compressNum - letterVal) // 26

        if compressNum < 26:  # for last letter will be less than 26 so then append the last
            decoded_text += Letter_Decoding(compressNum)
            decompress_numList.append(compressNum)

    decompress_numList.reverse()

    decompress_num = int(''.join([str(n).zfill(2) for n in decompress_numList]))

    decompress_numList = [str(n).zfill(2) for n in decompress_numList]

    decoded_text = decoded_text[::-1]

    return decompress_num, decompress_numList, decoded_text


def Print_Encrypted_Decrypt_Stmt(encryptedNumList, decryptedNumList, msg):
    print("Encrypted Compress NumList:", encryptedNumList)

    print("Decrypted Compress NumList:", decryptedNumList)
    decrypt_compress_num = int(''.join([str(x) for x in decryptedNumList]))
    print("Decrypted Compress Num: ", decrypt_compress_num)

    decompress_num, decompress_numList, decoded_text = DecompressEncodedText(decryptedNumList)
    print("Decrypted Decompressed Num:", decompress_num)
    print("Decrypted Decompressed NumList:", decompress_numList)
    print("Decrypted Decompressed Set:", end=" ")
    for i in decompress_numList:
        print(i+":"+Letter_Decoding(int(i)),end=", ")
    print("\nDecrypted Decoded Text:", decoded_text)

    if decoded_text == msg:
        print("\nSuccess!! Original message match Decrypted Decompressed Message: " + decoded_text, "==", msg)
    else:
        print("\nError!! Original message NOT Match Decrypted Decompressed Message: " + decoded_text, "!=", msg)

# while True:
#     compressNum = NumCompression(input("Enter text to compress: "))
#     SplitCompressNum(compressNum)
