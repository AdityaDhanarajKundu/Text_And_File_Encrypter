from tkinter import *
from tkinter import messagebox, filedialog
import base64
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import binascii
import time
import threading
from tkinter.ttk import Progressbar

# AES Encryption/Decryption key size (256-bit key)
BLOCK_SIZE = 16
MAX_RETRIES = 3
LOCKOUT_TIME = 30  # Lockout duration in seconds

# Global variables to track retries and lockout state
retry_count = 0
lockout_start_time = None


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
        time.sleep(1)  # Ensure the progress bar stays visible for at least 1 seconds
        progress_window.destroy()

    # Run the task in a new thread to avoid blocking the GUI
    threading.Thread(target=lambda: [task(), close_progress()]).start()


def encrypt():
    password = code.get()

    if password == user_password:
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

                # Generate a random initialization vector (IV)
                iv = get_random_bytes(BLOCK_SIZE)

                # Encrypt the message using AES
                cipher = AES.new(key, AES.MODE_CBC, iv)
                ciphertext = cipher.encrypt(pad(message.encode('utf-8'), BLOCK_SIZE))

                # Encode the ciphertext and IV as base64 for storage/transmission
                encoded_cipher = base64.b64encode(iv + ciphertext).decode('utf-8')

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

    if password == user_password:
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

                # Decode the base64 encoded message to get the IV and ciphertext
                decoded_message = base64.b64decode(message)
                iv = decoded_message[:BLOCK_SIZE]
                ciphertext = decoded_message[BLOCK_SIZE:]

                # Decrypt the ciphertext using AES
                cipher = AES.new(key, AES.MODE_CBC, iv)
                decrypted_message = unpad(cipher.decrypt(ciphertext), BLOCK_SIZE).decode('utf-8')

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
            if password != user_password:
                messagebox.showerror("Alert!", "Invalid password for file encryption.")
                return

            with open(file_path, 'rb') as file:
                file_data = file.read()

            key = hashlib.sha256(password.encode()).digest()
            iv = get_random_bytes(BLOCK_SIZE)

            cipher = AES.new(key, AES.MODE_CBC, iv)
            ciphertext = cipher.encrypt(pad(file_data, BLOCK_SIZE))

            save_path = filedialog.asksaveasfilename(defaultextension=".enc", filetypes=[("Encrypted files", "*.enc")])
            if save_path:
                with open(save_path, 'wb') as file:
                    file.write(iv + ciphertext)

                messagebox.showinfo("Success", f"File encrypted successfully and saved at {save_path}")

        except Exception as e:
            messagebox.showerror("File Encryption Error", f"Failed to encrypt file: {str(e)}")


def decrypt_file():
    file_path = filedialog.askopenfilename(filetypes=[("Encrypted files", "*.enc")])

    if file_path:
        try:
            password = code.get()
            if password != user_password:
                messagebox.showerror("Alert!", "Invalid password for file decryption.")
                return

            with open(file_path, 'rb') as file:
                file_data = file.read()

            iv = file_data[:BLOCK_SIZE]
            ciphertext = file_data[BLOCK_SIZE:]

            key = hashlib.sha256(password.encode()).digest()

            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted_data = unpad(cipher.decrypt(ciphertext), BLOCK_SIZE)

            save_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
            if save_path:
                with open(save_path, 'wb') as file:
                    file.write(decrypted_data)

                messagebox.showinfo("Success", f"File decrypted successfully and saved at {save_path}")

        except Exception as e:
            messagebox.showerror("File Decryption Error", f"Failed to decrypt file: {str(e)}")


def main_screen():
    global screen
    global code
    global text1

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

    Label(text="Enter secret key for encryption and decryption", fg="black", font=("calibri", 13)).place(x=10, y=270)

    code = StringVar()
    Entry(textvariable=code, width=19, bd=0, font=("arial", 25), show="*").place(x=10, y=300)

    Button(text="Encrypt Text", height=2, width=23, bg="#ed3833", fg="white", bd=0, command=encrypt).place(x=10, y=350)
    Button(text="Decrypt Text", height=2, width=23, bg="#00bd56", fg="white", bd=0, command=decrypt).place(x=250, y=350)
    Button(text="Encrypt File", height=2, width=23, bg="#ed3833", fg="white", bd=0, command=encrypt_file).place(x=10, y=400)
    Button(text="Decrypt File", height=2, width=23, bg="#00bd56", fg="white", bd=0, command=decrypt_file).place(x=250, y=400)
    Button(text="Reset", height=2, width=50, bg="#1089ff", fg="white", bd=0, command=reset).place(x=10, y=450)

    screen.mainloop()


def set_password():
    global user_password

    screen = Tk()
    screen.geometry("300x200")
    screen.title("Set Password")

    Label(screen, text="Set your encryption/decryption password", fg="black", font=("calibri", 13)).pack(pady=20)

    password_var = StringVar()
    Entry(screen, textvariable=password_var, width=19, bd=0, font=("arial", 25), show="*").pack(pady=10)

    def save_password():
        global user_password
        user_password = password_var.get()
        if user_password == "":
            messagebox.showerror("Alert!", "Password cannot be empty")
        else:
            screen.destroy()
            main_screen()

    Button(screen, text="Save Password", height=2, width=20, bg="#1089ff", fg="white", bd=0, command=save_password).pack(pady=20)

    screen.mainloop()


# Start the application by asking the user to set a password
set_password()
