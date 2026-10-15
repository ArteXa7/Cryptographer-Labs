import json, base64, time, sys
from pathlib import Path
from Crypto.PublicKey import DSA, ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA1, SHA256, SHA512


HASHES = {"SHA1": SHA1, "SHA256": SHA256, "SHA512": SHA512}
CURVES = {"P-256": "P-256", "P-384": "P-384", "P-521": "P-521"}
DSA_SIZES = ("2048", "3072")
DSS_MODE = "deterministic-rfc6979"  # стабільні nonce для бенчу


def ask(prompt, default=None, allowed=None):
   while True:
       s = input("%s%s: " % (prompt, (" ["+default+"]") if default else "")).strip()
       if not s and default is not None: s = default
       if allowed and s.upper() not in [a.upper() for a in allowed]:
           print("✗ Дозволені значення:", ", ".join(allowed)); continue
       if s: return s


class DigitalSignature:
   def __init__(self, algo="ECDSA", hash_name="SHA256", curve="P-256", dsa_bits="2048"):
       self.algo = algo.upper(); self.hash_name = hash_name.upper()
       self.curve = curve; self.dsa_bits = int(dsa_bits); self.key = None


   def _h(self, data): return HASHES.get(self.hash_name, SHA256).new(data)


   def generate(self):
       if self.algo == "ECDSA": self.key = ECC.generate(curve=CURVES.get(self.curve, "P-256"))
       elif self.algo == "DSA": self.key = DSA.generate(self.dsa_bits)
       else: raise ValueError("Алгоритм має бути ECDSA або DSA")


   def save(self, priv_path, pub_path):
       if not self.key: raise ValueError("Нема приватного ключа.")
       Path(priv_path).write_text(self.key.export_key(format="PEM"))
       Path(pub_path).write_text(self.key.public_key().export_key(format="PEM"))


   def load_priv(self, path):
       pem = Path(path).read_text()
       try: self.key = ECC.import_key(pem); self.algo = "ECDSA"
       except Exception: self.key = DSA.import_key(pem); self.algo = "DSA"


   @staticmethod
   def load_pub(path):
       pem = Path(path).read_text()
       try: return "ECDSA", ECC.import_key(pem)
       except Exception: return "DSA", DSA.import_key(pem)


   def sign(self, data):
       if not self.key: raise ValueError("Нема приватного ключа.")
       return DSS.new(self.key, DSS_MODE).sign(self._h(data))


   @staticmethod
   def verify(data, sig, pub_key, hash_name="SHA256"):
       h = HASHES.get(hash_name.upper(), SHA256).new(data)
       try: DSS.new(pub_key, DSS_MODE).verify(h, sig); return True
       except ValueError: return False


def write_sig(path, algo, hash_name, file_name, sig):
   meta = {"algo": algo, "hash": hash_name, "ts": int(time.time()),
           "file": file_name, "sig_b64": base64.b64encode(sig).decode("ascii")}
   Path(path).write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")


def read_sig(path):
   meta = json.loads(Path(path).read_text(encoding="utf-8"))
   return meta["algo"], meta["hash"], meta.get("file",""), base64.b64decode(meta["sig_b64"])


def bench(ds, data, iters=200):
   t0=time.time(); sig=None
   for _ in range(iters): sig=ds.sign(data)
   t_sign=time.time()-t0
   pub=ds.key.public_key()
   t0=time.time()
   for _ in range(iters):
       if not DigitalSignature.verify(data, sig, pub, ds.hash_name): raise RuntimeError("verify fail")
   t_ver=time.time()-t0
   print("\n[bENCH] %s/%s  %s%s" % (ds.algo, ds.hash_name,
         ("curve="+ds.curve) if ds.algo=="ECDSA" else ("dsa_bits="+str(ds.dsa_bits)), ""))
   print("  iters=%d | sign: avg=%.3f ms/op ops/s=%.2f | verify: avg=%.3f ms/op ops/s=%.2f"
         % (iters, t_sign/iters*1000, iters/t_sign, t_ver/iters*1000, iters/t_ver))


def main():
   print("=== ЕЦП (DSA/ECDSA) — Лабораторна ===")
   algo = ask("Алгоритм (ECDSA/DSA)", "ECDSA", ["ECDSA","DSA"]).upper()
   hash_name = ask("Геш (SHA1/SHA256/SHA512)", "SHA256", list(HASHES.keys())).upper()


   if algo=="ECDSA":
       curve = ask("Крива (P-256/P-384/P-521)", "P-256", list(CURVES.keys()))
       ds = DigitalSignature(algo, hash_name, curve=curve)
   else:
       bits = ask("Розмір DSA ключа (2048/3072)", "2048", list(DSA_SIZES))
       ds = DigitalSignature(algo, hash_name, dsa_bits=bits)


   mode = ask("1) Згенерувати ключі  2) Завантажити приватний ключ", "1", ["1","2"])
   if mode=="1":
       ds.generate()
       if ask("Зберегти ключі у файли? (Y/N)", "Y", ["Y","N"]).upper()=="Y":
           ds.save(ask("priv key файл","priv.key"), ask("pub key файл","pub.key"))
           print("✓ Ключі збережено.")
   else:
       ds.load_priv(ask("Шлях до приватного ключа","priv.key"))
       print("✓ Завантажено приватний ключ (%s)"%ds.algo)


   in_file = ask("Файл для підпису","input.bin"); data = Path(in_file).read_bytes()
   t0=time.time(); sig=ds.sign(data); sign_dt=time.time()-t0
   sig_out = ask("Файл підпису (.sig)","%s.sig"%Path(in_file).name)
   write_sig(sig_out, ds.algo, ds.hash_name, Path(in_file).name, sig)
   print("✓ Підпис збережено →", sig_out); print("[i] Час підпису: %.4f с" % sign_dt)


   print("\n--- Перевірка підпису ---")
   use_file = ask("Використати публічний ключ із файлу? (Y/N)","Y",["Y","N"]).upper()=="Y"
   if use_file: _, pub = DigitalSignature.load_pub(ask("Шлях до публічного ключа","pub.key"))
   else: pub = ds.key.public_key()


   algo_meta, hash_meta, file_meta, sig_bytes = read_sig(sig_out)
   if algo_meta.upper()!=ds.algo or hash_meta.upper()!=ds.hash_name:
       print("[warn] .sig meta: %s/%s; обрано: %s/%s"%(algo_meta,hash_meta,ds.algo,ds.hash_name))
   print("✓ Підпис ДІЙСНИЙ" if DigitalSignature.verify(data, sig_bytes, pub, ds.hash_name) else "✗ Підпис НЕДІЙСНИЙ")


   if ask("\nЗапустити бенчмарк? (Y/N)","Y",["Y","N"]).upper()=="Y":
       bench(ds, data, int(ask("Кількість ітерацій","200")))


if __name__=="__main__":
   try: main()
   except KeyboardInterrupt: print("\n^C Вихід"); sys.exit(1)
   except FileNotFoundError as e: print("Файл не знайдено:", e); sys.exit(2)
   except Exception as e: print("Помилка:", e); sys.exit(3)
