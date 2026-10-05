#!/usr/bin/env python3
"""Uso: python3 proteger.py index_original.html "SENHA" index_protegido.html
Requer: pip install cryptography"""
import sys, os, base64, json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

src, senha, dst = sys.argv[1], sys.argv[2], sys.argv[3]
ITER = 250000
html = open(src, "rb").read()
salt, iv = os.urandom(16), os.urandom(12)
key = PBKDF2HMAC(hashes.SHA256(), 32, salt, ITER).derive(senha.encode())
ct = AESGCM(key).encrypt(iv, html, None)
b64 = lambda b: base64.b64encode(b).decode()
payload = json.dumps({"s": b64(salt), "i": b64(iv), "c": b64(ct), "n": ITER})

page = """<!DOCTYPE html>
<html lang="pt-BR"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="robots" content="noindex,nofollow">
<title>Acesso restrito</title>
<style>
html,body{height:100%;margin:0}
body{background:#0f1420;color:#fff;font-family:system-ui,sans-serif;display:flex;align-items:center;justify-content:center}
form{display:flex;flex-direction:column;gap:12px;width:min(320px,86vw);text-align:center}
h2{margin:0 0 6px;font-weight:600}
input,button{padding:12px;font-size:16px;border-radius:8px;border:0}
button{background:#c9a24a;color:#111;font-weight:600;cursor:pointer}
#e{color:#ff7b7b;min-height:1.2em;margin:0;font-size:14px}
</style></head><body>
<form id="f"><h2>Acesso restrito</h2>
<input id="p" type="password" placeholder="Senha" autocomplete="current-password" autofocus>
<button type="submit">Entrar</button><p id="e"></p></form>
<script>
const D=__PAYLOAD__;
const u=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
async function abrir(pw){
  const km=await crypto.subtle.importKey("raw",new TextEncoder().encode(pw),"PBKDF2",false,["deriveKey"]);
  const k=await crypto.subtle.deriveKey({name:"PBKDF2",salt:u(D.s),iterations:D.n,hash:"SHA-256"},km,{name:"AES-GCM",length:256},false,["decrypt"]);
  const pt=await crypto.subtle.decrypt({name:"AES-GCM",iv:u(D.i)},k,u(D.c));
  return new TextDecoder().decode(pt);
}
async function entrar(pw){
  const h=await abrir(pw);
  try{sessionStorage.setItem("pw",pw)}catch(e){}
  document.open();document.write(h);document.close();
}
document.getElementById("f").addEventListener("submit",async ev=>{
  ev.preventDefault();
  const e=document.getElementById("e");e.textContent="Verificando...";
  try{await entrar(document.getElementById("p").value)}
  catch(x){e.textContent="Senha incorreta";}
});
try{const s=sessionStorage.getItem("pw");if(s)entrar(s).catch(()=>sessionStorage.removeItem("pw"))}catch(e){}
</script></body></html>"""
open(dst, "w", encoding="utf-8").write(page.replace("__PAYLOAD__", payload))
print("OK ->", dst)
