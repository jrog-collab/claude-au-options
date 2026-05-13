#!/usr/bin/env python3
"""Encrypt src/wizard.html into index.html with a password gate.

Usage: python3 encrypt.py <password>
The plaintext in src/ is git-ignored; only the encrypted index.html is committed.
"""
import sys, os, base64, hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PBKDF2_ITERS = 200_000

def b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")

def main():
    if len(sys.argv) != 2:
        sys.exit("usage: python3 encrypt.py <password>")
    password = sys.argv[1].encode("utf-8")
    here = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(here, "src", "wizard.html"), "rb") as f:
        plaintext = f.read()

    salt = os.urandom(16)
    iv = os.urandom(12)
    key = hashlib.pbkdf2_hmac("sha256", password, salt, PBKDF2_ITERS, dklen=32)
    ct = AESGCM(key).encrypt(iv, plaintext, None)  # ct includes 16-byte GCM tag at end

    shell = SHELL.replace("__SALT__", b64(salt)) \
                 .replace("__IV__", b64(iv)) \
                 .replace("__ITERS__", str(PBKDF2_ITERS)) \
                 .replace("__CIPHERTEXT__", b64(ct))
    with open(os.path.join(here, "index.html"), "w", encoding="utf-8") as f:
        f.write(shell)
    print(f"encrypted {len(plaintext):,} bytes -> index.html ({len(ct):,} bytes ciphertext)")

SHELL = r"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Claude in Australia — Deployment Options</title>
<style>
  :root{--bg:#F0EEE6;--ink:#191919;--muted:#6B6255;--line:#E0DACC;--accent:#CC785C;--accent-d:#A85A3F}
  *{box-sizing:border-box}body{margin:0;font-family:ui-sans-serif,-apple-system,"Segoe UI",Roboto,sans-serif;background:var(--bg);color:var(--ink);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px}
  .gate{background:#fff;border:1px solid var(--line);border-radius:14px;padding:32px 34px;max-width:380px;width:100%;box-shadow:0 4px 24px rgba(0,0,0,.06)}
  .logo{font-family:ui-serif,Georgia,serif;font-size:13px;letter-spacing:.12em;text-transform:uppercase;color:var(--muted);margin-bottom:6px}
  h1{font-family:ui-serif,Georgia,serif;font-weight:500;font-size:22px;margin:0 0 6px}
  p{color:var(--muted);font-size:14px;margin:0 0 18px}
  input{width:100%;font:inherit;padding:12px 14px;border:1.5px solid var(--line);border-radius:8px;font-size:15px}
  input:focus{outline:none;border-color:var(--accent)}
  button{width:100%;margin-top:12px;font:inherit;font-weight:600;padding:12px;border:none;border-radius:8px;background:var(--accent);color:#fff;cursor:pointer}
  button:hover{background:var(--accent-d)}button:disabled{background:var(--line);color:var(--muted);cursor:wait}
  .err{color:#B05050;font-size:13px;margin-top:10px;min-height:18px}
</style></head>
<body>
<form class="gate" id="gate" autocomplete="off">
  <div class="logo">Anthropic · Australia</div>
  <h1>Claude deployment options</h1>
  <p>Enter the access password to continue.</p>
  <input id="pw" type="password" placeholder="Password" autofocus/>
  <button id="go" type="submit">Unlock</button>
  <div class="err" id="err"></div>
</form>
<script>
const SALT="__SALT__",IV="__IV__",ITERS=__ITERS__;
const CT="__CIPHERTEXT__";
const b64d=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
async function deriveKey(pw){
  const enc=new TextEncoder();
  const base=await crypto.subtle.importKey("raw",enc.encode(pw),"PBKDF2",false,["deriveKey"]);
  return crypto.subtle.deriveKey(
    {name:"PBKDF2",salt:b64d(SALT),iterations:ITERS,hash:"SHA-256"},
    base,{name:"AES-GCM",length:256},false,["decrypt"]);
}
async function unlock(pw){
  const key=await deriveKey(pw);
  const pt=await crypto.subtle.decrypt({name:"AES-GCM",iv:b64d(IV)},key,b64d(CT));
  return new TextDecoder().decode(pt);
}
const form=document.getElementById("gate"),pwEl=document.getElementById("pw"),
      btn=document.getElementById("go"),err=document.getElementById("err");
const KEY="auopt_pw";
async function attempt(pw,remember){
  btn.disabled=true;err.textContent="";
  try{
    const html=await unlock(pw);
    if(remember){try{localStorage.setItem(KEY,pw)}catch(e){}}
    document.open();document.write(html);document.close();
  }catch(e){
    err.textContent="Incorrect password.";btn.disabled=false;pwEl.select();
    try{localStorage.removeItem(KEY)}catch(e){}
  }
}
form.addEventListener("submit",e=>{e.preventDefault();attempt(pwEl.value,true)});
try{const cached=localStorage.getItem(KEY);if(cached)attempt(cached,false)}catch(e){}
</script></body></html>
"""

if __name__ == "__main__":
    main()
