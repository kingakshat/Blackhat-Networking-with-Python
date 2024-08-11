
import random
import string



def caesar_encrypt(plain_text, key):

    cipher_text = ''
    # plain_text = plain_text.upper()

    for c in plain_text:
        index = ord(c)
        index = (index + key) % 128
        cipher_text += chr(index)

    return cipher_text


def caesar_decrypt(cipher_text, key):

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

    print("String => ", random_string, "Key => ",key)

    encrypted = caesar_encrypt(random_string, key)
    print("encrypted string -> ", encrypted)
    print("decrypted -> ",caesar_decrypt(encrypted, key))

