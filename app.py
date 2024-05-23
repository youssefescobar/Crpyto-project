from flask import Flask, render_template, request
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

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
    if len(key) not in [16, 24, 32]:
        raise ValueError("Key must be 16, 24, or 32 bytes long")
    else:
        cipher = AES.new(key, AES.MODE_CBC)
        ciphertext = cipher.iv + cipher.encrypt(pad(plaintext.encode('utf-8'), AES.block_size))
    return ciphertext.hex()

def aes_decrypt(ciphertext, key):
    if len(key) not in [16, 24, 32]:
        raise ValueError("Key must be 16, 24, or 32 bytes long")
    key = key.encode('utf-8')  # Convert key to bytes
    iv = bytes.fromhex(ciphertext[:32])  # Extract IV from the first 32 characters (IV size for AES)
    ciphertext = bytes.fromhex(ciphertext[32:])  # Extract ciphertext from characters after IV
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
                key = get_random_bytes(16)
                result = aes_encrypt(text, key)
            elif 'decrypt' in request.form:
                result = aes_decrypt(text, key)
        else:
            result = "Invalid cipher selected"
        return render_template('index.html', result=result)
    

    return render_template('index.html', result='')

if __name__ == '__main__':
    app.run(debug=True)
