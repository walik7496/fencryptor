import tkinter as tk
from tkinter import filedialog, ttk
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

# key for example (64 bytes):  1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef

def pad(data):
    block_size = algorithms.AES.block_size // 8
    padding_length = block_size - (len(data) % block_size)
    padding_value = bytes([padding_length] * padding_length)
    return data + padding_value

def unpad(data):
    padding_length = data[-1]
    return data[:-padding_length]

def encrypt_file(file_path, key):
    with open(file_path, 'rb') as f:
        data = f.read()
    
    backend = default_backend()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=backend)
    encryptor = cipher.encryptor()
    
    encrypted_data = encryptor.update(pad(data)) + encryptor.finalize()
    
    with open(file_path + '.enc', 'wb') as f:
        f.write(iv + encrypted_data)

def decrypt_file(encrypted_file_path, key):
    with open(encrypted_file_path, 'rb') as f:
        data = f.read()
    
    iv = data[:16]
    encrypted_data = data[16:]
    
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=backend)
    decryptor = cipher.decryptor()
    
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    
    with open(encrypted_file_path[:-4], 'wb') as f:
        f.write(unpad(decrypted_data))

def encrypt_files():
    key = os.urandom(32)  # 256-bit key
    files = filedialog.askopenfilenames()
    if files:
        progress_bar['maximum'] = len(files)
        for idx, file in enumerate(files, start=1):
            progress_bar['value'] = idx
            progress_bar.update()
            encrypt_file(file, key)
        progress_bar['value'] = 0
        tk.messagebox.showinfo("Encryption", "Encryption complete.")

def decrypt_files():
    key = bytes.fromhex(key_entry.get())  # Convert hex string to bytes
    files = filedialog.askopenfilenames()
    if files:
        progress_bar['maximum'] = len(files)
        for idx, file in enumerate(files, start=1):
            progress_bar['value'] = idx
            progress_bar.update()
            decrypt_file(file, key)
        progress_bar['value'] = 0
        tk.messagebox.showinfo("Decryption", "Decryption complete.")

# GUI
root = tk.Tk()
root.title("File Encryptor")

frame = tk.Frame(root)
frame.pack(padx=10, pady=10)

encrypt_button = tk.Button(frame, text="Encrypt Files", command=encrypt_files)
encrypt_button.grid(row=0, column=0, padx=5, pady=5)

decrypt_button = tk.Button(frame, text="Decrypt Files", command=decrypt_files)
decrypt_button.grid(row=0, column=1, padx=5, pady=5)

key_label = tk.Label(frame, text="Encryption Key:")
key_label.grid(row=1, column=0, padx=5, pady=5)

key_entry = tk.Entry(frame)
key_entry.grid(row=1, column=1, padx=5, pady=5)

progress_bar = ttk.Progressbar(frame, orient="horizontal", length=200, mode="determinate")
progress_bar.grid(row=2, columnspan=2, pady=5)

root.mainloop()
