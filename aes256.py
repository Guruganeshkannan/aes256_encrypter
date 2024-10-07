#***This code is used to encrypt and decrypt a file in sha256bit this code is written by guruganesh on 07-10-2024 ****
#***this code is a prototype so there will be some bug on the feel free to fix it or improve the code**** 
#***dont forget to give credits to the author of the code if use this code****
#***Also this is my first code that i have uploaded on github****
import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import os
import base64

# Key derivation function for AES-256
def derive_key(password: str, salt: bytes):
    key_length = 32  # AES-256 uses a 256-bit key (32 bytes)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=key_length,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return key

# Encrypt file using AES-256
def encrypt_file(file_data: bytes, password: str):
    salt = os.urandom(16)  # 128-bit salt
    key = derive_key(password, salt)
    iv = os.urandom(16)  # 128-bit IV for AES-256
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # PKCS7 padding to ensure block size compatibility
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(file_data) + padder.finalize()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # Return base64 encoded (salt + IV + encrypted data)
    return base64.b64encode(salt + iv + encrypted_data)

# Decrypt file using AES-256
def decrypt_file(encrypted_data: bytes, password: str):
    encrypted_data = base64.b64decode(encrypted_data)
    
    salt = encrypted_data[:16]  # Extract 128-bit salt
    iv = encrypted_data[16:32]  # Extract 128-bit IV
    cipher_text = encrypted_data[32:]  # Encrypted content
    
    key = derive_key(password, salt)
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    decrypted_data = decryptor.update(cipher_text) + decryptor.finalize()

    # PKCS7 unpadding to remove padding after decryption
    unpadder = padding.PKCS7(128).unpadder()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()

    return unpadded_data

# GUI setup
def select_file():
    file_path = filedialog.askopenfilename()
    return file_path

def save_file(data, default_extension=None):
    file_path = filedialog.asksaveasfilename(defaultextension=default_extension)
    if file_path:
        with open(file_path, 'wb') as f:
            f.write(data)

def encrypt_action():
    file_path = select_file()
    password = password_entry.get()

    if not file_path or not password:
        messagebox.showwarning("Warning", "Please select a file and enter a password.")
        return

    try:
        with open(file_path, 'rb') as f:
            file_data = f.read()
        
        encrypted_data = encrypt_file(file_data, password)
        save_file(encrypted_data, ".enc")
        messagebox.showinfo("Success", "File encrypted successfully!")
    except Exception as e:
        messagebox.showerror("Error", f"Encryption failed: {e}")

def decrypt_action():
    file_path = select_file()
    password = password_entry.get()

    if not file_path or not password:
        messagebox.showwarning("Warning", "Please select a file and enter a password.")
        return

    try:
        with open(file_path, 'rb') as f:
            encrypted_data = f.read()

        decrypted_data = decrypt_file(encrypted_data, password)
        
        file_extension = filedialog.asksaveasfilename(
            defaultextension=".*", title="Save Decrypted File As",
            filetypes=[("All Files", "*.*")]
        )
        if file_extension:
            with open(file_extension, 'wb') as f:
                f.write(decrypted_data)
        
        messagebox.showinfo("Success", "File decrypted successfully!")
    except Exception as e:
        messagebox.showerror("Error", f"Decryption failed: {e}")

# GUI Application
app = tk.Tk()
app.title("AES-256 Encryption and Decryption Tool|by guruganesh")
app.geometry("400x200")

# Labels and Buttons
password_label = tk.Label(app, text="Enter Password:")
password_label.pack(pady=10)

password_entry = tk.Entry(app, show="*", width=30)
password_entry.pack(pady=5)

encrypt_button = tk.Button(app, text="Encrypt File", command=encrypt_action)
encrypt_button.pack(pady=10)

decrypt_button = tk.Button(app, text="Decrypt File", command=decrypt_action)
decrypt_button.pack(pady=10)

app.mainloop()
