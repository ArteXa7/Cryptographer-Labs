import random


def power_mod(base, exp, mod):
   """Швидке піднесення до степеня за модулем."""
   result = 1
   base %= mod
   while exp > 0:
       if exp % 2 == 1:
           result = (result * base) % mod
       exp //= 2
       base = (base * base) % mod
   return result


def generate_keys(p, g, x):
   """Генерація відкритого та закритого ключів."""
   y = power_mod(g, x, p)
   return (p, g, y), x  # (публічний ключ), (приватний ключ)


def encrypt(message, public_key):
   """Шифрування текстового повідомлення."""
   p, g, y = public_key
   k = random.randint(1, p - 2)
   a = power_mod(g, k, p)
   cipher = []
   for char in message:
       m = ord(char)
       b = (power_mod(y, k, p) * m) % p
       cipher.append((a, b))
   return cipher


def decrypt(cipher, private_key, p):
   """Дешифрування тексту."""
   message = ''
   for a, b in cipher:
       s = power_mod(a, private_key, p)
       m = (b * pow(s, -1, p)) % p
       message += chr(m)
   return message


def save_cipher(cipher, filename):
   with open(filename, 'w') as f:
       for a, b in cipher:
           f.write(f"{a},{b}\n")


def load_cipher(filename):
   cipher = []
   with open(filename, 'r') as f:
       for line in f:
           a, b = map(int, line.strip().split(','))
           cipher.append((a, b))
   return cipher


def main():
   print("=== Алгоритм Ель-Гамаля ===")
   mode = input("Оберіть режим (e - шифрування, d - дешифрування): ").strip().lower()


   if mode == 'e':
       infile = input("Введіть ім'я вхідного файлу: ")
       outfile = input("Введіть ім'я вихідного файлу: ")


       p = int(input("Введіть просте число p: "))
       g = int(input("Введіть первісний корінь g: "))
       x = int(input("Введіть закритий ключ x: "))


       public_key, private_key = generate_keys(p, g, x)


       with open(infile, 'r', encoding='utf-8') as f:
           message = f.read()


       cipher = encrypt(message, public_key)
       save_cipher(cipher, outfile)
       print("Файл зашифровано та збережено.")


   elif mode == 'd':
       infile = input("Введіть ім'я вхідного (зашифрованого) файлу: ")
       outfile = input("Введіть ім'я вихідного (розшифрованого) файлу: ")


       p = int(input("Введіть p: "))
       x = int(input("Введіть закритий ключ x: "))


       cipher = load_cipher(infile)
       message = decrypt(cipher, x, p)


       with open(outfile, 'w', encoding='utf-8') as f:
           f.write(message)


       print("Файл успішно розшифровано.")
   else:
       print("Невірний вибір режиму.")


if __name__ == "__main__":
   main()


