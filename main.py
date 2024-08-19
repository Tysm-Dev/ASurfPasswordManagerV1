import tkinter as tk
from tkinter import messagebox
from cryptography.fernet import Fernet, InvalidToken
import json
import os

# Functions for managing data
def generate_key():
    return Fernet.generate_key()

def load_key():
    if os.path.exists("secret.key"):
        with open("secret.key", "rb") as key_file:
            key = key_file.read()
            if len(key) == 44:
                return key
            else:
                raise ValueError("The loaded key is invalid.")
    else:
        key = generate_key()
        with open("secret.key", "wb") as key_file:
            key_file.write(key)
        return key

def encrypt_and_store_data(user_data):
    key = load_key()
    fernet = Fernet(key)
    
    data = json.dumps(user_data)
    encrypted_data = fernet.encrypt(data.encode())
    
    with open("encrypted_data.bin", "wb") as file:
        file.write(encrypted_data)

def decrypt_and_load_data():
    key = load_key()
    fernet = Fernet(key)
    
    if os.path.exists("encrypted_data.bin"):
        try:
            with open("encrypted_data.bin", "rb") as file:
                encrypted_data = file.read()
            decrypted_data = fernet.decrypt(encrypted_data).decode()
            user_data = json.loads(decrypted_data)
            return user_data
        except InvalidToken:
            messagebox.showerror("Error", "Invalid token. The key or the encrypted file might be corrupted.")
            return {}
        except Exception as e:
            messagebox.showerror("Error", f"Error decrypting the data: {e}")
            return {}
    else:
        return {}

# GUI Functions
def add_user():
    username = entry_username.get()
    password = entry_password.get()
    
    if username and password:
        user_data = decrypt_and_load_data()
        user_data[username] = password
        encrypt_and_store_data(user_data)
        messagebox.showinfo("Success", "User data has been saved.")
        entry_username.delete(0, tk.END)
        entry_password.delete(0, tk.END)
    else:
        messagebox.showwarning("Warning", "Please enter both a username and a password.")

def display_users():
    user_data = decrypt_and_load_data()
    if user_data:
        display_text = "Stored user data:\n"
        for username, password in user_data.items():
            display_text += f"Username: {username}, Password: {password}\n"
    else:
        display_text = "No user data found."
    
    messagebox.showinfo("User Data", display_text)

def change_password():
    username = entry_username.get()
    old_password = entry_password.get()
    new_password = entry_new_password.get()
    
    if username and old_password and new_password:
        user_data = decrypt_and_load_data()
        if username in user_data and user_data[username] == old_password:
            user_data[username] = new_password
            encrypt_and_store_data(user_data)
            messagebox.showinfo("Success", "Password has been changed.")
            entry_username.delete(0, tk.END)
            entry_password.delete(0, tk.END)
            entry_new_password.delete(0, tk.END)
        else:
            messagebox.showwarning("Warning", "Username or password is incorrect.")
    else:
        messagebox.showwarning("Warning", "Please fill in all required fields.")

# Main GUI window
root = tk.Tk()
root.title("User Data Management")

# Username input
tk.Label(root, text="Username:").pack(pady=5)
entry_username = tk.Entry(root)
entry_username.pack(pady=5)

# Password input
tk.Label(root, text="Password:").pack(pady=5)
entry_password = tk.Entry(root, show="*")
entry_password.pack(pady=5)

# New password input
tk.Label(root, text="New Password:").pack(pady=5)
entry_new_password = tk.Entry(root, show="*")
entry_new_password.pack(pady=5)

# Buttons
tk.Button(root, text="Add User Data", command=add_user).pack(pady=10)
tk.Button(root, text="Display User Data", command=display_users).pack(pady=10)
tk.Button(root, text="Change Password", command=change_password).pack(pady=10)

# Display the window
root.mainloop()
