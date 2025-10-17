# E751(-1,1): y^2 = x^3 - x + 1 (mod 751)
# Генеруюча точка G = (0, 1)


p = 751
a = -1
b = 1
G = (0, 1)




def mod_inv(x, p):
   """Знаходження оберненого елемента за модулем p"""
   return pow(x, -1, p)




class EllipticCurve:
   def __init__(self, a, b, p):
       self.a = a
       self.b = b
       self.p = p


   def add_points(self, P, Q):
       """Додавання двох точок на кривій"""
       if P == (0, 0):
           return Q
       if Q == (0, 0):
           return P
       if P == Q:
           lam = ((3 * P[0] ** 2 + self.a) * mod_inv(2 * P[1], self.p)) % self.p
       else:
           lam = ((Q[1] - P[1]) * mod_inv(Q[0] - P[0], self.p)) % self.p


       x3 = (lam ** 2 - P[0] - Q[0]) % self.p
       y3 = (lam * (P[0] - x3) - P[1]) % self.p
       return (x3, y3)


   def mul_point(self, k, P):
       """Множення точки P на число k"""
       R = (0, 0)
       for _ in range(k):
           R = self.add_points(R, P)
       return R




class ECCElGamal:
   def __init__(self, curve, G):
       self.curve = curve
       self.G = G


   def generate_keys(self, private_key):
       """Генерація публічного ключа"""
       public_key = self.curve.mul_point(private_key, self.G)
       return public_key


   def encrypt(self, message_points, public_key, k):
       """Шифрування списку точок (повідомлення)"""
       encrypted = []
       for M in message_points:
           C1 = self.curve.mul_point(k, self.G)
           kY = self.curve.mul_point(k, public_key)
           C2 = self.curve.add_points(M, kY)
           encrypted.append((C1, C2))
       return encrypted


   def decrypt(self, cipher_pairs, private_key):
       """Дешифрування списку пар точок (шифротексту)"""
       decrypted = []
       for C1, C2 in cipher_pairs:
           S = self.curve.mul_point(private_key, C1)
           S_inv = (S[0], -S[1] % p)
           M = self.curve.add_points(C2, S_inv)
           decrypted.append(M)
       return decrypted




def text_to_points(text):
   """Перетворює символи у точки (для спрощення — x = код символу, y = sqrt(x^3 - x + 1 mod p))"""
   points = []
   for ch in text:
       x = ord(ch)
       y2 = (x**3 - x + 1) % p
       # знаходимо y, який задовольняє y^2 ≡ y2 (mod p)
       y = None
       for i in range(p):
           if (i * i) % p == y2:
               y = i
               break
       if y is None:
           y = 1  # запасне значення
       points.append((x, y))
   return points




def points_to_text(points):
   """Відновлення тексту із координати X"""
   return ''.join(chr(P[0] % 256) for P in points)




def save_to_file(filename, data):
   with open(filename, 'w') as f:
       for C1, C2 in data:
           f.write(f"{C1[0]},{C1[1]};{C2[0]},{C2[1]}\n")




def load_from_file(filename):
   data = []
   with open(filename, 'r') as f:
       for line in f:
           part1, part2 = line.strip().split(';')
           x1, y1 = map(int, part1.split(','))
           x2, y2 = map(int, part2.split(','))
           data.append(((x1, y1), (x2, y2)))
   return data




def main():
   print("=== Криптосистема на еліптичних кривих E751(-1,1) ===")
   mode = input("Оберіть режим (e - шифрування, d - дешифрування): ").strip().lower()


   curve = EllipticCurve(a, b, p)
   ecc = ECCElGamal(curve, G)


   if mode == 'e':
       infile = input("Введіть ім'я вхідного файлу: ")
       outfile = input("Введіть ім'я вихідного файлу: ")


       private_key = int(input("Введіть свій приватний ключ (x): "))
       k = int(input("Введіть випадкове число k: "))


       with open(infile, 'r', encoding='utf-8') as f:
           text = f.read()


       message_points = text_to_points(text)
       public_key = ecc.generate_keys(private_key)
       encrypted = ecc.encrypt(message_points, public_key, k)


       save_to_file(outfile, encrypted)
       print("Файл успішно зашифровано.")


   elif mode == 'd':
       infile = input("Введіть ім'я вхідного (зашифрованого) файлу: ")
       outfile = input("Введіть ім'я вихідного (розшифрованого) файлу: ")


       private_key = int(input("Введіть приватний ключ (x): "))


       cipher_data = load_from_file(infile)
       decrypted_points = ecc.decrypt(cipher_data, private_key)


       text = points_to_text(decrypted_points)
       with open(outfile, 'w', encoding='utf-8') as f:
           f.write(text)


       print("Файл успішно розшифровано.")
   else:
       print("Невірний режим. Використовуйте 'e' або 'd'.")




if __name__ == "__main__":
   main()


