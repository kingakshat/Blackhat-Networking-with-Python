import random
import string
import Caesar_cipher as enc

def caesar_brute_force_decrypt(cipher_text, key):

    plain_text = ''

    for c in cipher_text:
        index = ord(c)
        index = (index - key) % 128
        plain_text += chr(index)

    return plain_text


if __name__ == '__main__':

    m = 'abc'

    random_string = ''.join(random.choice(string.ascii_letters) for _ in range(16))
    key = random_number = random.randint(1, 128)

    print("String => ", random_string)

    encrypted = enc.caesar_encrypt(random_string, key)
    print("encrypted string -> ", encrypted)
    
    for i in range(1,128):
        op = caesar_brute_force_decrypt(encrypted, i)
        print(f"testing key {i} => decrypted -> ",op)
        if op == random_string:
            print("Cracked key =>",i)
            break

