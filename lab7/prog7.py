import time
import secrets


class DiffieHellman:
   def __init__(self, p, g):
       self.p = p
       self.g = g


   def gen_priv(self):
       return secrets.randbelow(self.p - 2) + 2  # 2..p-1


   def gen_pub(self, priv):
       return pow(self.g, priv, self.p)


   def secret(self, priv, other_pub):
       return pow(other_pub, priv, self.p)




def read_int(msg, default=None):
   s = input(msg)
   if s.strip() == "" and default is not None:
       return default
   return int(s)




def benchmark(dh, n):
   # класичний DH: фіксовані ключі, багаторазове обчислення секрету
   a = dh.gen_priv()
   b = dh.gen_priv()
   A = dh.gen_pub(a)
   B = dh.gen_pub(b)


   t1 = time.perf_counter()
   for _ in range(n):
       dh.secret(a, B)
   dh_time = (time.perf_counter() - t1) * 1000 / n


   # EDH: на кожну ітерацію нові ключі
   t2 = time.perf_counter()
   for _ in range(n):
       a = dh.gen_priv()
       b = dh.gen_priv()
       A = dh.gen_pub(a)
       B = dh.gen_pub(b)
       s1 = dh.secret(a, B)
       s2 = dh.secret(b, A)
       if s1 != s2:
           raise ValueError("Помилка обміну")
   edh_time = (time.perf_counter() - t2) * 1000 / n


   return dh_time, edh_time




def main():
   print("=== Діффі–Геллман (DH / EDH) ===")


   use_default = input("Використати типові p,g? (Enter = так, n = ні): ").strip().lower()
   if use_default == "n":
       p = read_int("p = ")
       g = read_int("g = ")
   else:
       p = 23
       g = 5
       print("p = 23, g = 5 (демо)")


   dh = DiffieHellman(p, g)


   # Демонстрація обміну
   a = dh.gen_priv()
   b = dh.gen_priv()
   A = dh.gen_pub(a)
   B = dh.gen_pub(b)
   s1 = dh.secret(a, B)
   s2 = dh.secret(b, A)


   print("\n--- Обмін ключами ---")
   print("A_priv =", a)
   print("A_pub  =", A)
   print("B_priv =", b)
   print("B_pub  =", B)
   print("secret A =", s1)
   print("secret B =", s2)
   print("Секрети збігаються?" , "так" if s1 == s2 else "ні")


   # Оцінка швидкодії
   n = read_int("\nКількість ітерацій для заміру (Enter = 1000): ", 1000)
   dh_t, edh_t = benchmark(dh, n)


   print("\n--- Швидкодія ---")
   print("DH  (фіксовані ключі):   {:.6f} мс/операція".format(dh_t))
   print("EDH (нові ключі щораз):  {:.6f} мс/операція".format(edh_t))
   print("\nГотово.")




if __name__ == "__main__":
   main()
