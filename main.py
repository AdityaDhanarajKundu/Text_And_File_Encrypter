from tkinter import *
from tkinter import messagebox
import base64

def decrypt():
    password = code.get()

    if password == user_password:
        screen2 = Toplevel(screen)
        screen2.title("Decryption")
        screen2.geometry("400x200")
        screen2.configure(bg="#00bd56")

        message = text1.get(1.0, END)
        decode_message = message.encode("ascii")
        base64_bytes = base64.b64decode(decode_message)
        decrypt = base64_bytes.decode("ascii")

        Label(screen2, text="DECRYPTED", font="arial", fg="white", bg="#00bd56").place(x=10, y=0)
        text2 = Text(screen2, font="Robote 10", bg="white", relief=GROOVE, wrap=WORD, bd=0)
        text2.place(x=10, y=40, width=380, height=150)

        text2.insert(END, decrypt)

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

        message = text1.get(1.0, END)
        encode_message = message.encode("ascii")
        base64_bytes = base64.b64encode(encode_message)
        encrypt = base64_bytes.decode("ascii")

        Label(screen1, text="ENCRYPTED", font="arial", fg="white", bg="#ed3833").place(x=10, y=0)
        text2 = Text(screen1, font="Robote 10", bg="white", relief=GROOVE, wrap=WORD, bd=0)
        text2.place(x=10, y=40, width=380, height=150)

        text2.insert(END, encrypt)

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


set_password()