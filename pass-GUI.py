import tkinter as tk
from tkinter import ttk, messagebox
import secrets

def get_password() -> None:

    alphabet = ""
    if use_upper_var.get():
        alphabet += "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    if use_lower_var.get():
        alphabet += "abcdefghijklmnopqrstuvwxyz"
    if use_digits_var.get():
        alphabet += "0123456789"
    if use_special_var.get():
        alphabet += "!@#$%^&*()-_=+[]{};:'\",.<>?/|\\`~"


    if alphabet == "":
        messagebox.showwarning("Error", "No checkboxes are chosen.")
        return
    
    try:
        length = int(password_length.get())
    except Exception as e:
        length = 32
    
    password = ""
    for _ in range(length):
        password += secrets.choice(alphabet)

    password_entry.delete(0, tk.END)
    password_entry.insert(0, password)


def get_phrase() -> None:

    with open("phrases.txt", "r") as f:
        try:
            num = int(phrase_length.get())
        except Exception as e:
            num = 7

        text = f.read()
        arr = text.split()
        words = arr[1::2]
        r_words = [secrets.choice(words) for _ in range(num)]
        sep = '-'
    
        phrase_entry.delete(0, tk.END)
        phrase_entry.insert(0, sep.join(r_words))

root = tk.Tk()
root.title("Password & Phrase Generator")
root.geometry("500x360")
root.resizable(True, False)

password_frame = ttk.LabelFrame(root, text="Password generation", padding=10)
password_frame.pack(fill="x", padx=10, pady=10)

for i in range(4):
    password_frame.grid_columnconfigure(i, weight=1)

password_entry = ttk.Entry(password_frame)
password_entry.grid(row=0, column=0, columnspan=4, pady=5, sticky="ew")

use_upper_var = tk.BooleanVar(value=True)
use_lower_var = tk.BooleanVar(value=True)
use_digits_var = tk.BooleanVar(value=True)
use_special_var = tk.BooleanVar(value=True)

use_upper = ttk.Checkbutton(password_frame, text="ABC", variable=use_upper_var)
use_lower = ttk.Checkbutton(password_frame, text="abc", variable=use_lower_var)
use_digits = ttk.Checkbutton(password_frame, text="123", variable=use_digits_var)
use_special = ttk.Checkbutton(password_frame, text="special", variable=use_special_var)

use_upper.grid(row=1, column=0, sticky="w", padx=5)
use_lower.grid(row=1, column=1, sticky="w", padx=5)
use_digits.grid(row=1, column=2, sticky="w", padx=5)
use_special.grid(row=1, column=3, sticky="w", padx=5)

ttk.Label(password_frame, text="Length:").grid(row=2, column=0, sticky="e", padx=5, pady=5)
password_length = ttk.Spinbox(password_frame, from_=4, to=128, width=8)
password_length.grid(row=2, column=1, sticky="w")

generate_pass_btn = ttk.Button(password_frame, text="Generate", command=get_password)
generate_pass_btn.grid(row=3, column=0, columnspan=4, pady=5, sticky="ew")

phrase_frame = ttk.LabelFrame(root, text="Phrase generator", padding=10)
phrase_frame.pack(fill="x", padx=10, pady=5)

for i in range(3):
    phrase_frame.grid_columnconfigure(i, weight=1)

phrase_entry = ttk.Entry(phrase_frame)
phrase_entry.grid(row=0, column=0, columnspan=3, pady=5, sticky="ew")

ttk.Label(phrase_frame, text="Words:").grid(row=1, column=0, sticky="e", padx=5, pady=5)
phrase_length = ttk.Spinbox(phrase_frame, from_=2, to=20, width=8)
phrase_length.grid(row=1, column=1, sticky="w")

generate_phrase_btn = ttk.Button(phrase_frame, text="Generate", command=get_phrase)
generate_phrase_btn.grid(row=2, column=0, columnspan=3, pady=5, sticky="ew")

root.mainloop()