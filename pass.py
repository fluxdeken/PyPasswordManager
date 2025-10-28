import argparse
from secrets import choice

parser = argparse.ArgumentParser(
    prog="Password generator",
    description="Program for creating cryptographically secure passwords")

parser.add_argument("-len", "--length", type=int, default=16)
parser.add_argument("-m", "--mix", action="store_true")
parser.add_argument("-l", "--lower", action="store_true")
parser.add_argument("-u", "--upper", action="store_true")
parser.add_argument("-n", "--numbers", action="store_true")
parser.add_argument("-s", "--special",  action="store_true")
args = parser.parse_args()

alphabet = ""

if args.lower:
    alphabet += "abcdefghijklmnopqrstuvwxyz"

if args.upper:
    alphabet += "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

if args.numbers:
    alphabet += "0123456789"

if args.special:
    alphabet += "!@#$%^&*()-_=+[]{};:'\",.<>?/|\\`~"

if args.mix:
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{};:'\",.<>?/|\\`~"

if len(alphabet) == 0:
    print("No characters were chosen.")
else:
    password = ""
    for _ in range(args.length):
        password += choice(alphabet)
    print(password)