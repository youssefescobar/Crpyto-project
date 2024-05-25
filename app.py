from flask import Flask, render_template, request
from Crypto.Cipher import AES
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

def aes_encrypt(plaintext):
    key = get_random_bytes(16)  # Generate a random key
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.iv + cipher.encrypt(pad(plaintext.encode('utf-8'), AES.block_size))
    return key.hex() + ciphertext.hex()  # Concatenate key and ciphertext

def aes_decrypt(ciphertext_with_key):
    key_hex = ciphertext_with_key[:32]  # Extract key part
    ciphertext_hex = ciphertext_with_key[32:]  # Extract ciphertext part
    
    key = bytes.fromhex(key_hex)  # Convert hex key to bytes
    ciphertext = bytes.fromhex(ciphertext_hex)  # Convert hex ciphertext to bytes
    
    iv = ciphertext[:16]  # Extract IV from the first 16 bytes (IV size for AES)
    ciphertext = ciphertext[16:]  # Extract ciphertext from bytes after IV
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return decrypted_data.decode('utf-8')
def transposition_encrypt(message, key):
    # Remove spaces from the message
    message = message.replace(" ", "")
    
    # Determine the number of columns and rows needed
    num_of_columns = len(key)
    num_of_rows = len(message) // num_of_columns
    if len(message) % num_of_columns != 0:
        num_of_rows += 1
    
    # Pad the message so that it fits into the grid perfectly
    padding_length = num_of_rows * num_of_columns - len(message)
    message += 'X' * padding_length  # Using 'X' as padding character
    
    # Create a 2D array to hold the characters
    grid = [['' for _ in range(num_of_columns)] for _ in range(num_of_rows)]
    
    # Fill the grid with characters from the message
    index = 0
    for row in range(num_of_rows):
        for col in range(num_of_columns):
            grid[row][col] = message[index]
            index += 1
    
    # Read the columns in the order specified by the key
    cipher_text = ""
    for num in key:
        col = int(num) - 1
        for row in range(num_of_rows):
            cipher_text += grid[row][col]
    
    return cipher_text
def transposition_decrypt(cipher_text, key):
    # Determine the number of columns and rows
    num_of_columns = len(key)
    num_of_rows = len(cipher_text) // num_of_columns
    
    # Create a 2D array to hold the characters
    grid = [['' for _ in range(num_of_columns)] for _ in range(num_of_rows)]
    
    # Fill the grid column by column based on the key
    index = 0
    for num in key:
        col = int(num) - 1
        for row in range(num_of_rows):
            grid[row][col] = cipher_text[index]
            index += 1
    
    # Read the rows to form the decrypted message
    plain_text = ""
    for row in range(num_of_rows):
        for col in range(num_of_columns):
            plain_text += grid[row][col]
    
    # Remove padding characters (if any)
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




@app.route('/', methods=['GET', 'POST'])
def home():
    if request.method == 'POST':
        key = request.form['key']
        text = request.form['inputText']
        cipher = request.form['cipher']
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
        elif cipher == 'rail-fence':
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
                result = des_encrypt(text, key)
            elif 'decrypt' in request.form:
                result = des_decrypt(text, key)
        elif cipher == 'aes':
            if 'encrypt' in request.form:
                encrypted_text = aes_encrypt(text)
                result = encrypted_text 
            elif 'decrypt' in request.form:
                result = aes_decrypt(text)
        else:
            result = "Invalid cipher selected"
        return render_template('index.html', result=result)
    

    return render_template('index.html', result='')

if __name__ == '__main__':
    app.run(debug=True)
