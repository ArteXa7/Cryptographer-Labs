import math


def gcd(a, b):
   while b != 0:
       a, b = b, a % b
   return a


def rabin_encrypt(m, n):
   """Шифрування повідомлення"""
   return (m * m) % n


def rabin_decrypt(c, p, q):
   """Дешифрування повідомлення"""
   n = p * q


   # Обчислення квадратних коренів за модулем p і q
   mp = pow(c, (p + 1) // 4, p)
   mq = pow(c, (q + 1) // 4, q)


   # Розв’язання за допомогою китайської теореми про залишки
   yp = pow(p, -1, q)
   yq = pow(q, -1, p)


   r1 = (yp * p * mq + yq * q * mp) % n
   r2 = n - r1
   r3 = (yp * p * mq - yq * q * mp) % n
   r4 = n - r3


   return [r1, r2, r3, r4]  # чотири можливі результати


def main():
   print("=== Алгоритм Рабіна ===")
   mode = input("Оберіть режим (e - шифрування, d - дешифрування): ").strip().lower()


   if mode == 'e':
       infile = input("Введіть ім'я вхідного файлу: ")
       outfile = input("Введіть ім'я вихідного файлу: ")


       p = int(input("Введіть просте число p (3 mod 4): "))
       q = int(input("Введіть просте число q (3 mod 4): "))


       n = p * q


       with open(infile, 'r', encoding='utf-8') as f:
           text = f.read()


       cipher = [rabin_encrypt(ord(ch), n) for ch in text]


       with open(outfile, 'w') as f:
           f.write(','.join(map(str, cipher)))


       print(f"Файл зашифровано. Відкритий ключ n = {n}")


   elif mode == 'd':
       infile = input("Введіть ім'я вхідного (зашифрованого) файлу: ")
       outfile = input("Введіть ім'я вихідного файлу: ")


       p = int(input("Введіть p: "))
       q = int(input("Введіть q: "))


       with open(infile, 'r') as f:
           cipher = list(map(int, f.read().split(',')))


       message = ''
       for c in cipher:
           roots = rabin_decrypt(c, p, q)
           # вибираємо правильний символ (зазвичай найменший, який є друкованим)
           m = min(roots)
           if 32 <= m <= 126:
               message += chr(m % 256)
           else:
               message += '?'


       with open(outfile, 'w', encoding='utf-8') as f:
           f.write(message)


       print("Файл успішно розшифровано.")


   else:
       print("Невірний вибір режиму.")


if __name__ == "__main__":
   main()


