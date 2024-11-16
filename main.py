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
from tkinter.ttk import Progressbar,Combobox

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

password_manager = PasswordManager()

# Global variables to track retries and lockout state
retry_count = 0
lockout_start_time = None
# user_password = None  # To hold the salted password hash
encryption_mode = "AES-CBC"


def show_progress_bar(window, task):
    # Create a Toplevel window for the progress bar
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
        time.sleep(1)  # Ensure the progress bar stays visible for at least 1 second
        progress_window.destroy()

    # Run the task in a new thread to avoid blocking the GUI
    threading.Thread(target=lambda: [task(), close_progress()]).start()

def encrypt():
    password = code.get()

    if password_manager.verify_password(password):  # Verify using the salted hash
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
                # Hash the password to create a 32-byte key for AES
                key = hashlib.sha256(password.encode()).digest()

                if encryption_mode == "AES-CBC":
                    # Generate a random initialization vector (IV)
                    iv = get_random_bytes(BLOCK_SIZE)

                    # Encrypt the message using AES
                    cipher = AES.new(key, AES.MODE_CBC, iv)
                    ciphertext = cipher.encrypt(pad(message.encode('utf-8'), BLOCK_SIZE))

                    # Encode the ciphertext and IV as base64 for storage/transmission
                    encoded_cipher = base64.b64encode(iv + ciphertext).decode('utf-8')
                
                elif encryption_mode == "AES-GCM":
                    cipher = AES.new(key, AES.MODE_GCM)
                    ciphertext, tag = cipher.encrypt_and_digest(message.encode('utf-8'))
                    encoded_cipher = base64.b64encode(cipher.nonce + tag + ciphertext).decode('utf-8')

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

def decrypt():
    global retry_count, lockout_start_time

    # Check if the user is locked out
    if lockout_start_time:
        elapsed_time = time.time() - lockout_start_time
        if elapsed_time < LOCKOUT_TIME:
            remaining_time = LOCKOUT_TIME - int(elapsed_time)
            messagebox.showerror("Locked Out", f"Too many failed attempts. Try again in {remaining_time} seconds.")
            return
        else:
            # Reset lockout after the lockout time passes
            lockout_start_time = None
            retry_count = 0

    password = code.get()

    if password_manager.verify_password(password):  # Verify using the salted hash
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
                # Hash the password to create a 32-byte key for AES
                key = hashlib.sha256(password.encode()).digest()

                if encryption_mode == "AES-CBC":
                    # Decode the base64 encoded message to get the IV and ciphertext
                    decoded_message = base64.b64decode(message)
                    iv = decoded_message[:BLOCK_SIZE]
                    ciphertext = decoded_message[BLOCK_SIZE:]
                    # Decrypt the ciphertext using AES
                    cipher = AES.new(key, AES.MODE_CBC, iv)
                    decrypted_message = unpad(cipher.decrypt(ciphertext), BLOCK_SIZE).decode('utf-8')
                
                elif encryption_mode == "AES-GCM":
                    decoded_message = base64.b64decode(message)
                    nonce = decoded_message[:16]
                    tag = decoded_message[16:32]
                    ciphertext = decoded_message[32:]
                    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                    decrypted_message = cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8')

                Label(screen2, text="DECRYPT", font="arial", fg="white", bg="#00bd56").place(x=10, y=0)
                text2 = Text(screen2, font="Robote 10", bg="white", relief=GROOVE, wrap=WORD, bd=0)
                text2.place(x=10, y=40, width=480, height=230)
                text2.insert(END, decrypted_message)

                # Reset retry counter upon successful decryption
                retry_count = 0

            except (binascii.Error, ValueError):
                messagebox.showerror("Decryption Error", "The encrypted message is corrupted or the wrong password was used.")
            except Exception as e:
                messagebox.showerror("Decryption Error", f"Failed to decrypt: {str(e)}")

        show_progress_bar(screen, process_decryption)

    elif password == "":
        messagebox.showerror("Alert!", "Please enter a password")

    else:
        retry_count += 1
        if retry_count >= MAX_RETRIES:
            lockout_start_time = time.time()  # Start the lockout timer
            messagebox.showerror("Locked Out", f"Too many failed attempts. You are locked out for {LOCKOUT_TIME} seconds.")
        else:
            remaining_attempts = MAX_RETRIES - retry_count
            messagebox.showerror("Alert!", f"Invalid password. {remaining_attempts} attempt(s) remaining.")

def encrypt_file():
    file_path = filedialog.askopenfilename()

    if file_path:
        try:
            password = code.get()
            if not password_manager.verify_password(password):  # Verify using the salted hash
                messagebox.showerror("Alert!", "Invalid password for file encryption.")
                return

            with open(file_path, 'rb') as file:
                file_data = file.read()

            key = hashlib.sha256(password.encode()).digest()
            iv = get_random_bytes(BLOCK_SIZE)

            if encryption_mode == "AES-CBC":
                cipher = AES.new(key, AES.MODE_CBC, iv)
                ciphertext = cipher.encrypt(pad(file_data, BLOCK_SIZE))
                encrypted_data = iv + ciphertext
            elif encryption_mode == "AES-GCM":
                cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
                ciphertext, tag = cipher.encrypt_and_digest(file_data)
                encrypted_data = cipher.nonce + tag + ciphertext

            save_path = filedialog.asksaveasfilename(defaultextension=".enc", filetypes=[("Encrypted files", "*.enc")])
            if save_path:
                with open(save_path, 'wb') as file:
                    file.write(encrypted_data)

                messagebox.showinfo("Success", f"File encrypted successfully and saved at {save_path}")

        except Exception as e:
            messagebox.showerror("File Encryption Error", f"Failed to encrypt file: {str(e)}")

def decrypt_file():
    file_path = filedialog.askopenfilename(filetypes=[("Encrypted files", "*.enc")])

    if file_path:
        try:
            password = code.get()
            if not password_manager.verify_password(password):  # Verify using the salted hash
                messagebox.showerror("Alert!", "Invalid password for file decryption.")
                return

            with open(file_path, 'rb') as file:
                file_data = file.read()

            key = hashlib.sha256(password.encode()).digest()

            if encryption_mode == "AES-CBC":
                iv = file_data[:BLOCK_SIZE]
                ciphertext = file_data[BLOCK_SIZE:]
                cipher = AES.new(key, AES.MODE_CBC, iv)
                decrypted_data = unpad(cipher.decrypt(ciphertext), BLOCK_SIZE)
            elif encryption_mode == "AES-GCM":
                nonce = file_data[:BLOCK_SIZE]
                tag = file_data[BLOCK_SIZE:BLOCK_SIZE+16]
                ciphertext = file_data[BLOCK_SIZE+16:]
                cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)

            save_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
            if save_path:
                with open(save_path, 'wb') as file:
                    file.write(decrypted_data)

                messagebox.showinfo("Success", f"File decrypted successfully and saved at {save_path}")

        except Exception as e:
            messagebox.showerror("File Decryption Error", f"Failed to decrypt file: {str(e)}")

def main_screen():
    global screen, code, text1, encryption_mode_combobox

    screen = Tk()
    screen.geometry("500x500")

    image_icon = PhotoImage(file="keys.png")
    screen.iconphoto(False, image_icon)
    screen.title("Text & File Encrypter and Decrypter")

    def reset():
        code.set("")
        text1.delete(1.0, END)

    Label(text="Enter text for encryption and decryption", fg="black", font=("calibri", 13)).place(x=10, y=10)
    text1 = Text(font="Robote 20", bg="white", relief=GROOVE, wrap=WORD, bd=0)
    text1.place(x=10, y=50, width=480, height=200)

    Label(text="Enter secret key for encryption and decryption", fg="black", font=("calibri", 13)).place(x=10, y=250)

    code = StringVar()
    Entry(textvariable=code, width=19, bd=0, font=("arial", 25), show="*").place(x=10, y=280)

    Label(text="Select Encryption Mode: ", fg="black", font=("calibri", 13)).place(x=10, y=330)
    encryption_mode_combobox = Combobox(screen, values=["AES-CBC", "AES-GCM"], state="readonly", width=10)
    encryption_mode_combobox.place(x=190, y=330)
    encryption_mode_combobox.current(0)

    def set_encryption_mode():
        global encryption_mode
        encryption_mode = encryption_mode_combobox.get()

    encryption_mode_combobox.bind("<<ComboboxSelected>>", lambda event: set_encryption_mode())

    Button(text="Encrypt Text", height=2, width=23, bg="#ed3833", fg="white", bd=0, command=encrypt).place(x=10, y=360)
    Button(text="Decrypt Text", height=2, width=23, bg="#00bd56", fg="white", bd=0, command=decrypt).place(x=280, y=360)
    Button(text="Encrypt File", height=2, width=23, bg="#ed3833", fg="white", bd=0, command=encrypt_file).place(x=10, y=400)
    Button(text="Decrypt File", height=2, width=23, bg="#00bd56", fg="white", bd=0, command=decrypt_file).place(x=280, y=400)
    Button(text="Reset", height=2, width=50, bg="#1089ff", fg="white", bd=0, command=reset).place(x=10, y=450)

    screen.mainloop()



# Start the application by asking the user to set a password
password_manager.set_password()
main_screen()
