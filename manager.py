import os
import sys
from pathlib import Path
from typing import *
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import json
import platform
from getpass import getpass
from colorama import init, Fore, Style
import pyperclip
from tabulate import tabulate
import copy

class Manager:
    
    def __init__(self):
        init()
        self.db_path = None
        self.key = None
        self.salt = None
        self.nonce = None

        self.aesgcm = None

        self.memory_cost = 131072
        self.time_cost = 4

        self.pswrds = []

        self.action: function = self.actions(self.new_db, self.load_db, sys.exit)
        if self.action:
            self.action()
            self.clear()
            while True:
                self.action = self.actions(self.create, self.edit, self.copy_pswrd, self.move, self.remove, self.change_db_pass, sys.exit)
                self.action()
                if not self.action is self.copy_pswrd:
                    self.save()
                self.clear()
    
    def clear(self):
        if platform.system() == "Windows":
            os.system("cls")
        else:
            os.system("clear")
    
    def save(self):
        self.aesgcm = AESGCM(self.key)
        self.nonce = os.urandom(12)
        
        ciphertext : bytes = self.aesgcm.encrypt(self.nonce, json.dumps(self.pswrds).encode("utf-8"), None)

        with open(self.db_path, "wb") as f:
            f.write(self.salt)
            f.write(self.nonce)
            f.write(ciphertext)

    def create(self):
        title = input("Title: ")
        login = input("Login: ")
        pswrd = getpass("Password: ")
        self.pswrds.append({"title": title, "login": login, "pswrd": pswrd})

    def edit(self):
        try:
            num = int(input("index: "))
            if num >= 0 and num < len(self.pswrds):
                title = input("Title: ")
                login = input("Login: ")
                pswrd = getpass("Password: ")
                self.pswrds[num] = {"title": title, "login": login, "pswrd": pswrd}
        except:
            pass
    
    def copy_pswrd(self):
        try:
            num = int(input("index: "))
            if num >= 0 and num < len(self.pswrds):
                pyperclip.copy(self.pswrds[num]['pswrd'])
                text = pyperclip.paste()
        except:
            pass

    def move(self):
        try:
            num1 = int(input("Index from: "))
            num2 = int(input("Index to: "))
            if num1 >= 0 and num1 < len(self.pswrds) and \
                num2 >= 0 and num2 < len(self.pswrds):
                el = self.pswrds.pop(num1)
                self.pswrds.insert(num2, el)
        except:
            pass

    def remove(self):
        try:
            num = int(input("Index from: "))
            if num >= 0 and num < len(self.pswrds):
                self.pswrds.pop(num)
        except:
            pass

    def load_db(self):
        path = Path(input("db path: "))
        if not path.exists():
            sys.exit("path not found")
        
        self.db_path = path
        if not self.db_path.is_absolute():
            self.db_path = self.db_path.absolute()

        pswrd = getpass("Password: ")

        with open(self.db_path, "rb") as f:
            self.salt = f.read(16)
            self.nonce = f.read(12)
            ciphertext = f.read()

            self.key = hash_secret_raw(
                secret=pswrd.encode("utf-8"),
                salt=self.salt,
                time_cost=self.time_cost,
                memory_cost=self.memory_cost,
                parallelism=4,
                hash_len=32,
                type=Type.ID
            )
            try:
                self.aesgcm = AESGCM(self.key)
                plaintext : bytes = self.aesgcm.decrypt(self.nonce, ciphertext, None)
                
                self.pswrds = json.loads(plaintext.decode("utf-8"))
            except:
                sys.exit("Wrong password.")

    def new_db(self) -> None:
        path = Path(input("db name: "))
        if path.exists():
            sys.exit("path already exists")
        
        self.db_path = Path.cwd().joinpath(path)
            
        pswrd1 = getpass("Password: ")
        pswrd2 = getpass("Password: ")
        if pswrd1 != pswrd2:
            sys.exit("Different passwords")
        
        self.salt = os.urandom(16)
        self.key = hash_secret_raw(
            secret=pswrd1.encode("utf-8"),
            salt=self.salt,
            time_cost=self.time_cost,
            memory_cost=self.memory_cost,
            parallelism=4,
            hash_len=32,
            type=Type.ID
        )

    def change_db_pass(self):
        pswrd1 = getpass("Password: ")
        pswrd2 = getpass("Password: ")
        if pswrd1 != pswrd2:
            sys.exit("Different passwords")
        self.salt = os.urandom(16)
        self.key = hash_secret_raw(
            secret=pswrd1.encode("utf-8"),
            salt=self.salt,
            time_cost=self.time_cost,
            memory_cost=self.memory_cost,
            parallelism=4,
            hash_len=32,
            type=Type.ID
        )
        self.save()

    def actions(self, *funcs) -> Optional[function]:
        lst:list[function] = []
        
        if len(self.pswrds) > 0:
            copy_pswrds = copy.deepcopy(self.pswrds)
            for x in copy_pswrds:
                x["pswrd"] = "***"
            
            print(tabulate(copy_pswrds, headers="keys", showindex=True, tablefmt="grid"))

        menu = Fore.GREEN
        for i, f in enumerate(funcs):
            menu += f"[{i} - {f.__name__ if hasattr(f, '__name__') else f.__func__.__name__}] "
            lst.append(f)
        menu += Style.RESET_ALL
        menu += "\n"
        print(menu)

        try:
            action = int(input("\naction: "))
        except:
            sys.exit("Couldn't read an action.")

        if action < 0 or action > len(funcs) - 1:
            sys.exit("Wrong number.")
        else:
            return lst[action]
    
mngr = Manager()