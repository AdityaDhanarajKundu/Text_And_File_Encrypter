from tkinter import *
from tkinter import messagebox
import base64
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import binascii

# AES Encryption/Decryption key size (256-bit key)
BLOCK_SIZE = 16

def encrypt():
    password = code.get()
    
    if password == user_password:
        screen1 = Toplevel(screen)
        screen1.title("Encryption")
        screen1.geometry("400x200")
        screen1.configure(bg="#ed3833")

        message = text1.get(1.0, END)
        if not message.strip():
            messagebox.showerror("Error", "No text provided for encryption")
            return

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
            text2.place(x=10, y=40, width=380, height=150)
            text2.insert(END, encoded_cipher)

        except Exception as e:
            messagebox.showerror("Encryption Error", f"Failed to encrypt: {str(e)}")

    elif password == "":
        messagebox.showerror("Alert!", "Please enter a password")

    else:
        messagebox.showerror("Alert!", "Invalid password")


def decrypt():
    password = code.get()

    if password == user_password:
        screen2 = Toplevel(screen)
        screen2.title("Decryption")
        screen2.geometry("400x200")
        screen2.configure(bg="#00bd56")

        message = text1.get(1.0, END)
        if not message.strip():
            messagebox.showerror("Error", "No text provided for decryption")
            return

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
            text2.place(x=10, y=40, width=380, height=150)
            text2.insert(END, decrypted_message)

        except (binascii.Error, ValueError):
            messagebox.showerror("Decryption Error", "The encrypted message is corrupted or the wrong password was used.")
        except Exception as e:
            messagebox.showerror("Decryption Error", f"Failed to decrypt: {str(e)}")

    elif password == "":
        messagebox.showerror("Alert!", "Please enter a password")

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
