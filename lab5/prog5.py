import os, sys, random, hashlib


#Простий RSA клас
class RSA:
   def __init__(self, n=None, e=None, d=None):
       self.n, self.e, self.d = n, e, d


   @staticmethod
   def egcd(a,b):
       if not b: return (a,1,0)
       g,x,y = RSA.egcd(b, a%b)
       return (g, y, x - (a//b)*y)


   @staticmethod
   def modinv(a,m):
       g,x,_=RSA.egcd(a,m)
       return x%m if g==1 else None


   @staticmethod
   def is_prime(n, k=8):
       if n<2 or n%2==0: return n==2
       d,s=n-1,0
       while d%2==0: d//=2; s+=1
       for _ in range(k):
           a=random.randrange(2,n-1)
           x=pow(a,d,n)
           if x in (1,n-1): continue
           for __ in range(s-1):
               x=pow(x,2,n)
               if x==n-1: break
           else: return False
       return True


   @staticmethod
   def gen_prime(bits):
       while True:
           x=random.getrandbits(bits)|1|(1<<(bits-1))
           if RSA.is_prime(x): return x


   @classmethod
   def generate(cls, bits=512):
       p,q=cls.gen_prime(bits//2),cls.gen_prime(bits//2)
       while p==q: q=cls.gen_prime(bits//2)
       n,phi=p*q,(p-1)*(q-1)
       e=65537
       d=cls.modinv(e,phi)
       print("Ключі згенеровано.")
       return cls(n,e,d)


   def sign(self,m:int)->int: return pow(m,self.d,self.n)
   def verify(self,s:int)->int: return pow(s,self.e,self.n)


#Допоміжні функції
def file_to_int(f): return int.from_bytes(open(f,'rb').read() or b'\x00','big')
def int_to_bytes(i): return i.to_bytes((i.bit_length()+7)//8 or 1,'big')
def hash_file(f, algo):
   h=hashlib.new(algo)
   with open(f,'rb') as x:
       for c in iter(lambda:x.read(8192),b''): h.update(c)
   return int.from_bytes(h.digest(),'big')


#Основний застосунок
class RSASignApp:
   def __init__(self): self.rsa=None
   def run(self):
       print("=== RSA ЕЦП (recovery / detached) ===")
       while True:
           print("\n1) Генерація ключів\n2) Ввести e,d,n\n3) Підпис (recovery)\n4) Підпис (detached)\n5) Перевірити (recovery)\n6) Перевірити (detached)\n7) Вихід")
           c=input("Вибір: ")
           if c=='1': self.gen_keys()
           elif c=='2': self.input_keys()
           elif c=='3': self.sign_recovery()
           elif c=='4': self.sign_detached()
           elif c=='5': self.verify_recovery()
           elif c=='6': self.verify_detached()
           elif c=='7': break


   def gen_keys(self):
       bits=int(input("Розмір ключа (512/1024/2048): "))
       self.rsa=RSA.generate(bits)
       print(f"n={self.rsa.n.bit_length()} біт, e={self.rsa.e}")


   def input_keys(self):
       n=int(input("n=")); e=int(input("e=")); d=int(input("d="))
       self.rsa=RSA(n,e,d); print("Ключі завантажено.")


   #Recovery sign
   def sign_recovery(self):
       if not self.rsa: return print("Немає ключів.")
       inp, out = input("Вхідний файл: "), input("Файл підпису: ")
       m=file_to_int(inp)
       if m>=self.rsa.n: return print("M >= n. Використай detached.")
       s=self.rsa.sign(m); open(out,'w').write(hex(s)[2:])
       print("Підпис збережено.")


   def verify_recovery(self):
       sig, out = input("Файл підпису: "), input("Файл для відновлення: ")
       e=int(input("e=")); n=int(input("n="))
       s=int(open(sig).read(),16); m=pow(s,e,n)
       open(out,'wb').write(int_to_bytes(m))
       print("Повідомлення відновлено.")


   #Detached sign
   def sign_detached(self):
       if not self.rsa: return print("Немає ключів.")
       f=input("Файл для підпису: ")
       algo=input("Хеш-функція (md5/sha1/sha256): ").lower()
       h=hash_file(f,algo)
       s=self.rsa.sign(h); open(f+'.sig','w').write(hex(s)[2:])
       open(f+'.meta','w').write(algo)
       print("Підпис створено:",f+".sig")


   def verify_detached(self):
       f=input("Файл: "); sig=f+'.sig'
       if not os.path.exists(sig): return print("Немає файлу підпису.")
       algo=open(f+'.meta').read().strip()
       e=int(input("e=")); n=int(input("n="))
       s=int(open(sig).read(),16)
       hfile=hash_file(f,algo)
       hsig=pow(s,e,n)
       print("Підпис дійсний." if hfile==hsig else "Підпис НЕвалідний.")


#Запуск
if __name__=="__main__":
   try: RSASignApp().run()
   except KeyboardInterrupt: print("\nВихід.")


