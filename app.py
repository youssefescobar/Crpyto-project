from flask import Flask, render_template, request
from Crypto.Cipher import AES,DES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import string

app = Flask(__name__)

def caesar_encrypt(text, key):
    result = ""
    for char in text:
        if char.isalpha():
            shifted = ord(char) + key
            if char.islower():
                if shifted > ord('z'):
                    shifted -= 26
                elif shifted < ord('a'):
                    shifted += 26
            elif char.isupper():
                if shifted > ord('Z'):
                    shifted -= 26
                elif shifted < ord('A'):
                    shifted += 26
            result += chr(shifted)
        else:
            result += char
    return result

def caesar_decrypt(text, key):
    return caesar_encrypt(text, -key)

def aes_encrypt(plaintext, key):
    key = key.encode('utf-8')
    key = key[:16].ljust(16, b'\0')  
    cipher = AES.new(key, AES.MODE_ECB)
    padded_plaintext = pad(plaintext.encode('utf-8'), AES.block_size)
    ciphertext = cipher.encrypt(padded_plaintext)
    return ciphertext.hex()

def aes_decrypt(ciphertext, key):
    key = key.encode('utf-8')
    key = key[:16].ljust(16, b'\0')  
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = bytes.fromhex(ciphertext)
    decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return decrypted_data.decode('utf-8')
def transposition_encrypt(message, key):

    message = message.replace(" ", "")
    num_of_columns = len(key)
    num_of_rows = len(message) // num_of_columns
    if len(message) % num_of_columns != 0:
        num_of_rows += 1
    

    padding_length = num_of_rows * num_of_columns - len(message)
    message += 'X' * padding_length 
    
    
    grid = [['' for _ in range(num_of_columns)] for _ in range(num_of_rows)]
    
   
    index = 0
    for row in range(num_of_rows):
        for col in range(num_of_columns):
            grid[row][col] = message[index]
            index += 1
    
    cipher_text = ""
    for num in key:
        col = int(num) - 1
        for row in range(num_of_rows):
            cipher_text += grid[row][col]
    
    return cipher_text
def transposition_decrypt(cipher_text, key):

    num_of_columns = len(key)
    num_of_rows = len(cipher_text) // num_of_columns
    
    grid = [['' for _ in range(num_of_columns)] for _ in range(num_of_rows)]
    
    index = 0
    for num in key:
        col = int(num) - 1
        for row in range(num_of_rows):
            grid[row][col] = cipher_text[index]
            index += 1

    plain_text = ""
    for row in range(num_of_rows):
        for col in range(num_of_columns):
            plain_text += grid[row][col]

    plain_text = plain_text.rstrip('X')
    
    return plain_text

def vigenere_encrypt(plaintext, key):
    cipher = ""
    index = 0
    for char in plaintext:
        if char in string.ascii_lowercase:
            offset = ord(key[index % len(key)].lower()) - ord('a')
            encrypted = chr((ord(char) - ord('a') + offset) % 26 + ord('a'))
            cipher += encrypted
            index += 1
        elif char in string.ascii_uppercase:
            offset = ord(key[index % len(key)].lower()) - ord('a')
            encrypted = chr((ord(char) - ord('A') + offset) % 26 + ord('A'))
            cipher += encrypted
            index += 1
        else:
            cipher += char
    return cipher
def vigenere_decrypt(ciphertext, key):
    plaintext = ""
    index = 0
    for char in ciphertext:
        if char in string.ascii_lowercase:
            offset = ord(key[index % len(key)].lower()) - ord('a')
            decrypted = chr((ord(char) - ord('a') - offset + 26) % 26 + ord('a'))
            plaintext += decrypted
            index += 1
        elif char in string.ascii_uppercase:
            offset = ord(key[index % len(key)].lower()) - ord('a')
            decrypted = chr((ord(char) - ord('A') - offset + 26) % 26 + ord('A'))
            plaintext += decrypted
            index += 1
        else:
            plaintext += char
    return plaintext
def polyalphabetic_encrypt(plain_text, shifts_input):
    encrypted_text = ""
    shifts = list(map(int, shifts_input.split()))
    for i, char in enumerate(plain_text):
        if char.isalpha():
            shift = shifts[i % len(shifts)]
            base = ord('A') if char.isupper() else ord('a')
            encrypted_char = chr(((ord(char) - base + shift) % 26) + base)
            encrypted_text += encrypted_char
        else:
            encrypted_text += char
    return encrypted_text
def polyalphabetic_decrypt(encrypted_text, shifts):
    decrypted_text = ""
    shifts = list(map(int, shifts.split()))
    for i, char in enumerate(encrypted_text):
        if char.isalpha():
            shift = shifts[i % len(shifts)]
            base = ord('A') if char.isupper() else ord('a')
            decrypted_char = chr((ord(char) - base - shift) % 26 + base)
            decrypted_text += decrypted_char
        else:
            decrypted_text += char
    return decrypted_text
def monoalphabetic_encrypt(plain_text, key):
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    key = key.strip().upper()
    key_map = {alphabet[i]: key[i] for i in range(26)}
    plain_text = plain_text.strip()
    
    encrypted_text = ""
    for char in plain_text:
        if char.isalpha():
            if char.isupper():
                encrypted_text += key_map[char]
            else:
                encrypted_text += key_map[char.upper()].lower()
        else:
            encrypted_text += char
    return encrypted_text

def monoalphabetic_decrypt(encrypted_text, key):
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    key = key.strip().upper()
    encrypted_text = encrypted_text.strip()
    reverse_key_map = {key[i]: alphabet[i] for i in range(26)}
    
    decrypted_text = ""
    for char in encrypted_text:
        if char.isalpha():
            if char.isupper():
                decrypted_text += reverse_key_map[char]
            else:
                decrypted_text += reverse_key_map[char.upper()].lower()
        else:
            decrypted_text += char
    return decrypted_text

def des_encrypt(plaintext, key):
    key = key.encode('utf-8')
    cipher = DES.new(key, DES.MODE_ECB)
    padded_plaintext = pad(plaintext.encode('utf-8'), DES.block_size)
    ciphertext = cipher.encrypt(padded_plaintext)
    return ciphertext

def des_decrypt(ciphertext, key):
    key = key.encode('utf-8')
    cipher = DES.new(key, DES.MODE_ECB)
    decrypted_data = cipher.decrypt(ciphertext)
    plaintext = unpad(decrypted_data, DES.block_size)
    return plaintext.decode('utf-8')

def playfair_encrypt(plaintext, key):
    return playfair_cipher(plaintext, key, 'encrypt')

def playfair_decrypt(ciphertext, key):
    return playfair_cipher(ciphertext, key, 'decrypt')

def playfair_cipher(text, key, mode):
    alphabet = 'abcdefghiklmnopqrstuvwxyz'
    key = key.lower().replace(' ', '').replace('j', 'i')
    key_square = ''
    for letter in key + alphabet:
        if letter not in key_square:
            key_square += letter
            
    text = text.lower().replace(' ', '').replace('j', 'i')
    if len(text) % 2 == 1:
        text += 'x'
    digraphs = [text[i:i+2] for i in range(0, len(text), 2)]
def rail_fence_encrypt(text, key):
    key = int(key)
    rail = [['\n' for _ in range(len(text))] for _ in range(key)]
    dir_down = False
    row, col = 0, 0

    for char in text:
        if row == 0 or row == key - 1:
            dir_down = not dir_down
        rail[row][col] = char
        col += 1
        row += 1 if dir_down else -1

    encrypted_text = ''.join([''.join(row) for row in rail])
    return encrypted_text.replace('\n', '')

def rail_fence_decrypt(cipher, key):
    key = int(key)
    rail = [['\n' for _ in range(len(cipher))] for _ in range(key)]
    dir_down = None
    row, col = 0, 0

    for i in range(len(cipher)):
        if row == 0:
            dir_down = True
        if row == key - 1:
            dir_down = False
        rail[row][col] = '*'
        col += 1
        row += 1 if dir_down else -1

    index = 0
    for i in range(key):
        for j in range(len(cipher)):
            if rail[i][j] == '*' and index < len(cipher):
                rail[i][j] = cipher[index]
                index += 1

    decrypted_text = []
    row, col = 0, 0
    for i in range(len(cipher)):
        if row == 0:
            dir_down = True
        if row == key - 1:
            dir_down = False
        if rail[row][col] != '*':
            decrypted_text.append(rail[row][col])
            col += 1
        row += 1 if dir_down else -1

    return ''.join(decrypted_text)
 
def is_valid_key(cipher, key):
    if cipher in ["caesar", "transposition", "polyalphabetic"]:
        return key.isdigit()
    if cipher == "monoalphabetic":
        return len(key) == 26 and key.isalpha()
    return True




@app.route('/', methods=['GET', 'POST'])
def home():
    result = ''
    if request.method == 'POST':
        key = request.form['key']
        text = request.form['inputText']
        cipher = request.form['cipher']
        
        if not text:
            result = "Please enter the input text."
        elif not key:
            result = "Please enter the key."
        elif not is_valid_key(cipher, key):
            if cipher in ["caesar", "transposition", "polyalphabetic"]:
                result = f"The key for {cipher} must be a number."
            elif cipher == "monoalphabetic":
                result = "The key for monoalphabetic must be 26 letters."
            else:
                result = "Invalid key."
        else:
            try:
                if cipher == 'caesar':
                    if 'encrypt' in request.form:
                        result = caesar_encrypt(text, int(key))
                    elif 'decrypt' in request.form:
                        result = caesar_decrypt(text, int(key))
                elif cipher == 'vigenere':
                    if 'encrypt' in request.form:
                        result = vigenere_encrypt(text, key)
                    elif 'decrypt' in request.form:
                        result = vigenere_decrypt(text, key)
                elif cipher == 'transposition':
                    if 'encrypt' in request.form:
                        result = transposition_encrypt(text, key)
                    elif 'decrypt' in request.form:
                        result = transposition_decrypt(text, key)
                elif cipher == 'railfence':
                    if 'encrypt' in request.form:
                        result = rail_fence_encrypt(text, key)
                    elif 'decrypt' in request.form:
                        result = rail_fence_decrypt(text, key)
                elif cipher == 'playfair':
                    if 'encrypt' in request.form:
                        result = playfair_encrypt(text, key)
                    elif 'decrypt' in request.form:
                        result = playfair_decrypt(text, key)
                elif cipher == 'monoalphabetic':
                    if 'encrypt' in request.form:
                        result = monoalphabetic_encrypt(text, key)
                    elif 'decrypt' in request.form:
                        result = monoalphabetic_decrypt(text, key)
                elif cipher == 'polyalphabetic':
                    if 'encrypt' in request.form:
                        result = polyalphabetic_encrypt(text, key)
                    elif 'decrypt' in request.form:
                        result = polyalphabetic_decrypt(text, key)
                elif cipher == 'des':
                    if 'encrypt' in request.form:
                        result = des_encrypt(text, key).hex()
                    elif 'decrypt' in request.form:
                        result = des_decrypt(bytes.fromhex(text), key)
                elif cipher == 'aes':
                    if 'encrypt' in request.form:
                        result = aes_encrypt(text, key)
                    elif 'decrypt' in request.form:
                        result = aes_decrypt(text, key)
                else:
                    result = "Invalid cipher selected"
            except ValueError:
                result = "Please enter a valid key."
    
    return render_template('index.html', result=result)

if __name__ == '__main__':
    app.run(debug=True)
