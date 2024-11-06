import os
import hashlib
import base64
import binascii
import time
import threading
import re
from tkinter import *
from tkinter import messagebox, filedialog
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from tkinter.ttk import Progressbar

# AES Encryption/Decryption key size (256-bit key)
BLOCK_SIZE = 16
MAX_RETRIES = 3
LOCKOUT_TIME = 30  # Lockout duration in seconds

class PasswordManager:
    def __init__(self):
        self.user_password = None  # Stores the hashed password with salt
        self.retry_count = 0
        self.lockout_start_time = None

    def hash_password(self, password):
        salt = os.urandom(16)
        salted_hash = salt + hashlib.sha256(salt + password.encode()).digest()
        return salted_hash

    def verify_password(self, password):
        if self.user_password is None:
            return False
        salt = self.user_password[:16]
        expected_hash = self.user_password[16:]
        return hashlib.sha256(salt + password.encode()).digest() == expected_hash

    def validate_password(self, password):
        if len(password) < 8:
            return False, "Password must be at least 8 characters long."
        if not re.search(r"[A-Z]", password):
            return False, "Password must contain at least one uppercase letter."
        if not re.search(r"[a-z]", password):
            return False, "Password must contain at least one lowercase letter."
        if not re.search(r"[0-9]", password):
            return False, "Password must contain at least one digit."
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            return False, "Password must contain at least one special character."
        return True, None

    def set_password(self):
        screen = Tk()
        screen.geometry("300x400")
        screen.title("Set Password")

        Label(screen, text="Set your encryption/decryption password", fg="black", font=("calibri", 13)).pack(pady=20)
        Label(screen, text="Password must include:\n- At least 8 characters\n- At least one uppercase letter\n- One lowercase letter\n- One digit\n- One special character", fg="gray", font=("calibri", 10)).pack(pady=5)

        password_var = StringVar()
        Entry(screen, textvariable=password_var, width=19, bd=0, font=("arial", 25), show="*").pack(pady=10)

        def save_password():
            entered_password = password_var.get()
            is_valid, validation_message = self.validate_password(entered_password)
            if not is_valid:
                messagebox.showerror("Password Error", validation_message)
            else:
                self.user_password = self.hash_password(entered_password)
                screen.destroy()

        Button(screen, text="Save Password", height=2, width=20, bg="#1089ff", fg="white", bd=0, command=save_password).pack(pady=20)
        screen.mainloop()

    def check_lockout(self):
        if self.lockout_start_time:
            elapsed_time = time.time() - self.lockout_start_time
            if elapsed_time < LOCKOUT_TIME:
                remaining_time = LOCKOUT_TIME - int(elapsed_time)
                messagebox.showerror("Locked Out", f"Too many failed attempts. Try again in {remaining_time} seconds.")
                return True
            else:
                self.lockout_start_time = None
                self.retry_count = 0
        return False

    def attempt_login(self, password):
        if self.check_lockout():
            return False

        if self.verify_password(password):
            self.retry_count = 0
            return True
        else:
            self.retry_count += 1
            if self.retry_count >= MAX_RETRIES:
                self.lockout_start_time = time.time()
                messagebox.showerror("Locked Out", f"Too many failed attempts. You are locked out for {LOCKOUT_TIME} seconds.")
            else:
                remaining_attempts = MAX_RETRIES - self.retry_count
                messagebox.showerror("Alert!", f"Invalid password. {remaining_attempts} attempt(s) remaining.")
            return False

password_manager = PasswordManager()

# Progress bar function for UI tasks
def show_progress_bar(window, task):
    progress_window = Toplevel(window)
    progress_window.title("Processing")
    progress_window.geometry("300x100")
    progress_window.attributes('-topmost', True)
    Label(progress_window, text="Processing, please wait...").pack(pady=10)
    
    progress = Progressbar(progress_window, orient=HORIZONTAL, length=250, mode='indeterminate')
    progress.pack(pady=10)
    progress.start()

    def close_progress():
        progress.stop()
        time.sleep(1)
        progress_window.destroy()

    threading.Thread(target=lambda: [task(), close_progress()]).start()

# Text encryption function
# Updated encryption/decryption functions using AES-GCM for integrity checking

# Text encryption function
def encrypt():
    password = code.get()
    if password_manager.verify_password(password):
        screen1 = Toplevel(screen)
        screen1.title("Encryption")
        screen1.geometry("500x300")
        screen1.configure(bg="#ed3833")

        message = text1.get(1.0, END)
        if not message.strip():
            messagebox.showerror("Error", "No text provided for encryption")
            return

        def process_encryption():
            try:
                key = hashlib.sha256(password.encode()).digest()
                cipher = AES.new(key, AES.MODE_GCM)  # Use GCM mode for integrity check
                ciphertext, tag = cipher.encrypt_and_digest(message.encode('utf-8'))
                iv = cipher.nonce
                encoded_cipher = base64.b64encode(iv + tag + ciphertext).decode('utf-8')

                Label(screen1, text="ENCRYPT", font="arial", fg="white", bg="#ed3833").place(x=10, y=0)
                text2 = Text(screen1, font="Robote 10", bg="white", relief=GROOVE, wrap=WORD, bd=0)
                text2.place(x=10, y=40, width=480, height=230)
                text2.insert(END, encoded_cipher)
            except Exception as e:
                messagebox.showerror("Encryption Error", f"Failed to encrypt: {str(e)}")

        show_progress_bar(screen, process_encryption)
    elif password == "":
        messagebox.showerror("Alert!", "Please enter a password")
    else:
        messagebox.showerror("Alert!", "Invalid password")

# Text decryption function
def decrypt():
    password = code.get()
    if password_manager.attempt_login(password):
        screen2 = Toplevel(screen)
        screen2.title("Decryption")
        screen2.geometry("500x300")
        screen2.configure(bg="#00bd56")

        message = text1.get(1.0, END)
        if not message.strip():
            messagebox.showerror("Error", "No text provided for decryption")
            return

        def process_decryption():
            try:
                key = hashlib.sha256(password.encode()).digest()
                decoded_message = base64.b64decode(message)
                iv, tag, ciphertext = decoded_message[:16], decoded_message[16:32], decoded_message[32:]

                cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
                decrypted_message = cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8')

                # Decrypted message shown
                Label(screen2, text="DECRYPT", font="arial", fg="white", bg="#00bd56").place(x=10, y=0)
                text2 = Text(screen2, font="Robote 10", bg="white", relief=GROOVE, wrap=WORD, bd=0)
                text2.place(x=10, y=40, width=480, height=230)
                text2.insert(END, decrypted_message)

            except ValueError:
                # If the password is incorrect or the message is corrupted (Integrity check failure)
                messagebox.showerror("Decryption Error", "The message has been corrupted.")
            except Exception as e:
                # Any other general errors
                messagebox.showerror("Decryption Error", f"Failed to decrypt: {str(e)}")

        show_progress_bar(screen, process_decryption)
    elif password == "":
        messagebox.showerror("Alert!", "Please enter a password")
    else:
        messagebox.showerror("Alert!", "Invalid password")

# File encryption function
def encrypt_file():
    password = code.get()
    if password_manager.verify_password(password):
        file_path = filedialog.askopenfilename()
        if not file_path:
            return

        def process_file_encryption():
            try:
                key = hashlib.sha256(password.encode()).digest()
                cipher = AES.new(key, AES.MODE_GCM)
                iv = cipher.nonce

                with open(file_path, 'rb') as f:
                    plaintext = f.read()
                ciphertext, tag = cipher.encrypt_and_digest(plaintext)
                encrypted_data = base64.b64encode(iv + tag + ciphertext)

                encrypted_file_path = file_path + ".enc"
                with open(encrypted_file_path, 'wb') as ef:
                    ef.write(encrypted_data)
                messagebox.showinfo("File Encryption", f"File encrypted successfully as {encrypted_file_path}")
            except Exception as e:
                messagebox.showerror("File Encryption Error", f"Failed to encrypt file: {str(e)}")

        show_progress_bar(screen, process_file_encryption)
    else:
        messagebox.showerror("Alert!", "Invalid password")

# File decryption function
def decrypt_file():
    password = code.get()
    if password_manager.attempt_login(password):
        file_path = filedialog.askopenfilename()
        if not file_path:
            return

        def process_file_decryption():
            try:
                key = hashlib.sha256(password.encode()).digest()

                with open(file_path, 'rb') as ef:
                    encrypted_data = base64.b64decode(ef.read())
                iv, tag, ciphertext = encrypted_data[:16], encrypted_data[16:32], encrypted_data[32:]

                cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
                plaintext = cipher.decrypt_and_verify(ciphertext, tag)

                decrypted_file_path = file_path.replace(".enc", "_decrypted")
                with open(decrypted_file_path, 'wb') as df:
                    df.write(plaintext)
                messagebox.showinfo("File Decryption", f"File decrypted successfully as {decrypted_file_path}")
            except ValueError:
                # Handle incorrect password or integrity check failure for files
                messagebox.showerror("File Decryption Error", "Incorrect password or the file has been corrupted.")
            except Exception as e:
                # General exception handling for file decryption
                messagebox.showerror("File Decryption Error", f"Failed to decrypt file: {str(e)}")

        show_progress_bar(screen, process_file_decryption)
    else:
        messagebox.showerror("Alert!", "Invalid password")

# GUI Setup
def main_screen():
    global screen, code, text1
    screen = Tk()
    screen.geometry("375x500")
    screen.title("Python Encryptor")

    def reset():
        code.set("")
        text1.delete(1.0, END)

    Label(text="Enter text for encryption and decryption", fg="black", font=("calibri", 13)).place(x=10, y=10)
    text1 = Text(font="Robote 20", bg="white", relief=GROOVE, wrap=WORD, bd=0)
    text1.place(x=10, y=50, width=355, height=100)

    Label(text="Enter secret key for encryption and decryption", fg="black", font=("calibri", 13)).place(x=10, y=170)
    code = StringVar()
    Entry(textvariable=code, width=19, bd=0, font=("arial", 25), show="*").place(x=10, y=200)

    Button(text="ENCRYPT", height="2", width=23, bg="#ed3833", fg="white", bd=0, command=encrypt).place(x=10, y=250)
    Button(text="DECRYPT", height="2", width=23, bg="#00bd56", fg="white", bd=0, command=decrypt).place(x=200, y=250)
    Button(text="ENCRYPT FILE", height="2", width=23, bg="#ed3833", fg="white", bd=0, command=encrypt_file).place(x=10, y=300)
    Button(text="DECRYPT FILE", height="2", width=23, bg="#00bd56", fg="white", bd=0, command=decrypt_file).place(x=200, y=300)
    Button(text="RESET", height="2", width=50, bg="#1089ff", fg="white", bd=0, command=reset).place(x=10, y=350)

    screen.mainloop()

# Set the initial password and start the application
password_manager.set_password()
main_screen()
