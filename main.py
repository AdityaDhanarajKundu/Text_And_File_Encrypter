from tkinter import *
from tkinter import messagebox
import base64
from Crypto.Cipher import AES
import hashlib
from Crypto.Util.Padding import pad, unpad

# AES uses blocks of fixed size, so we pad the text if needed
BLOCK_SIZE = 16

def encrypt_AES(message, password):
    # Generate a key from the password using SHA-256
    key = hashlib.sha256(password.encode()).digest()
    # Initialize the cipher with the key and a random IV (Initialization Vector)
    cipher = AES.new(key, AES.MODE_CBC)
    # Pad the message and encrypt it
    ciphertext_bytes = cipher.encrypt(pad(message.encode('utf-8'), BLOCK_SIZE))
    # Encode the IV and ciphertext to Base64 so they can be stored or displayed
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ciphertext = base64.b64encode(ciphertext_bytes).decode('utf-8')
    # Return the IV and ciphertext, which together represent the full encrypted message
    return iv + ":" + ciphertext

def decrypt_AES(encrypted_message, password):
    try:
        # Split the Base64-encoded message into IV and ciphertext
        iv, ciphertext = encrypted_message.split(":")
        # Decode the IV and ciphertext from Base64
        iv = base64.b64decode(iv)
        ciphertext = base64.b64decode(ciphertext)
        # Generate the same key from the password using SHA-256
        key = hashlib.sha256(password.encode()).digest()
        # Initialize the cipher with the key and the extracted IV
        cipher = AES.new(key, AES.MODE_CBC, iv)
        # Decrypt and unpad the message
        decrypted_message = unpad(cipher.decrypt(ciphertext), BLOCK_SIZE).decode('utf-8')
        return decrypted_message
    except (ValueError, KeyError):
        messagebox.showerror("Alert!", "Decryption failed. Invalid password or corrupted data.")
        return None

def decrypt():
    password = code.get()

    if password == user_password:
        screen2 = Toplevel(screen)
        screen2.title("Decryption")
        screen2.geometry("400x200")
        screen2.configure(bg="#00bd56")

        encrypted_message = text1.get(1.0, END).strip()  # Read and strip the text input
        decrypted_message = decrypt_AES(encrypted_message, password)

        if decrypted_message is not None:
            Label(screen2, text="DECRYPT", font="arial", fg="white", bg="#00bd56").place(x=10, y=0)
            text2 = Text(screen2, font="Robote 10", bg="white", relief=GROOVE, wrap=WORD, bd=0)
            text2.place(x=10, y=40, width=380, height=150)
            text2.insert(END, decrypted_message)

    elif password == "":
        messagebox.showerror("Alert!", "Input password")
    else:
        messagebox.showerror("Alert!", "Invalid password")

def encrypt():
    password = code.get()

    if password == user_password:
        screen1 = Toplevel(screen)
        screen1.title("Encryption")
        screen1.geometry("400x200")
        screen1.configure(bg="#ed3833")

        message = text1.get(1.0, END).strip()  # Read and strip the text input
        encrypted_message = encrypt_AES(message, password)

        Label(screen1, text="ENCRYPT", font="arial", fg="white", bg="#ed3833").place(x=10, y=0)
        text2 = Text(screen1, font="Robote 10", bg="white", relief=GROOVE, wrap=WORD, bd=0)
        text2.place(x=10, y=40, width=380, height=150)
        text2.insert(END, encrypted_message)

    elif password == "":
        messagebox.showerror("Alert!", "Input password")
    else:
        messagebox.showerror("Alert!", "Invalid password")

def main_screen():
    global screen
    global code
    global text1

    screen = Tk()
    screen.geometry("375x398")

    image_icon = PhotoImage(file="keys.png")
    screen.iconphoto(False, image_icon)
    screen.title("Text Encrypter and Decrypter")

    def reset():
        code.set("")
        text1.delete(1.0, END)

    Label(text="Enter text for encryption and decryption", fg="black", font=("calibri", 13)).place(x=10, y=10)
    text1 = Text(font="Robote 20", bg="white", relief=GROOVE, wrap=WORD, bd=0)
    text1.place(x=10, y=50, width=355, height=100)

    Label(text="Enter secret key for encryption and decryption", fg="black", font=("calibri", 13)).place(x=10, y=170)

    code = StringVar()
    Entry(textvariable=code, width=19, bd=0, font=("arial", 25), show="*").place(x=10, y=200)

    Button(text="Encrypt", height=2, width=23, bg="#ed3833", fg="white", bd=0, command=encrypt).place(x=10, y=250)
    Button(text="Decrypt", height=2, width=23, bg="#00bd56", fg="white", bd=0, command=decrypt).place(x=200, y=250)
    Button(text="Reset", height=2, width=50, bg="#1089ff", fg="white", bd=0, command=reset).place(x=10, y=300)

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
