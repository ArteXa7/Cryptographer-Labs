import math, struct


def egcd(a,b):
   if b==0: return a,1,0
   g,x,y=egcd(b,a%b); return g,y,x-(a//b)*y


def modinv(a,m): return egcd(a,m)[1]%m


def isprime(n):
   if n<2: return False
   for i in range(2,int(math.sqrt(n))+1):
       if n%i==0: return False
   return True


def factor(n):
   for i in range(2,int(math.sqrt(n))+1):
       if n%i==0: return i,n//i
   raise ValueError("Не вдалося факторизувати n")


class RSA:
   def __init__(s,e,n,p=None,q=None):
       s.e,s.n=e,n; s.p,s.q=p,q
       if not p or not q: s.p,s.q=factor(n)
       s.phi=(s.p-1)*(s.q-1); s.d=modinv(e,s.phi)


   def crypt(s,val,key): return pow(val,*key)


class RSACipher:
   def __init__(s,rsa):
       s.rsa=rsa
       s.modlen=(rsa.n.bit_length()+7)//8
       s.k=(rsa.n.bit_length()-1)//8


   def fileop(s,infile,outfile,mode):
       with open(infile,'rb') as f: data=f.read()
       if mode=='e':
           blocks=[int.from_bytes(data[i:i+s.k],'big') for i in range(0,len(data),s.k)]
           enc=b''.join(s.rsa.crypt(x,(s.rsa.e,s.rsa.n)).to_bytes(s.modlen,'big') for x in blocks)
           head=b'RSABIN'+struct.pack('>BQHH',1,len(data),s.k,s.modlen)
           open(outfile,'wb').write(head+enc)
       else:
           f=open(infile,'rb'); f.read(6); f.read(1)
           size,k,mod=struct.unpack('>QHH',f.read(12)); data=f.read()
           blocks=[int.from_bytes(data[i:i+mod],'big') for i in range(0,len(data),mod)]
           dec=b''.join(s.rsa.crypt(x,(s.rsa.d,s.rsa.n)).to_bytes(k,'big') for x in blocks)
           open(outfile,'wb').write(dec[:size])


if __name__=="__main__":
   print("=== RSA FILE CIPHER ===")
   m=input("(E)ncrypt/(D)ecrypt? ").lower()[0]
   inf=input("Вхідний файл: "); outf=input("Вихідний файл: ")
   e,n=int(input("e: ")),int(input("n=p*q: "))
   try: rsa=RSA(e,n)
   except: p=int(input("p: ")); q=int(input("q: ")); rsa=RSA(e,n,p,q)
   print(f"Ключі: d={rsa.d}, phi={rsa.phi}")
   RSACipher(rsa).fileop(inf,outf,'e' if m=='e' else 'd')
   print("Готово")