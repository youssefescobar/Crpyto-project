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
    key = b''.join([key] * 16)
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv) 
    padded_plaintext = pad(plaintext.encode(), AES.block_size)
    ciphertext = cipher.encrypt(padded_plaintext)
    encrypted_data = iv + ciphertext
    return encrypted_data

def aes_decrypt(encrypted_data, key):
    iv = encrypted_data[:16]
    actual_ciphertext = encrypted_data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext = cipher.decrypt(actual_ciphertext)
    plaintext = unpad(padded_plaintext, AES.block_size) 
    return plaintext.decode('utf-8')


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
