---
title: "DownUnderCTF 2025 Reverse Engineering Writeups"
description: "DownUnderCTF 2025 Reverse Engineering Writeups"
summary: "DownUnderCTF 2025 Reverse Engineering Writeups"
categories: ["Writeup"]
tags: ["Reverse"]
#externalUrl: ""
date: 2025-07-23
draft: false
authors:
  - blitzkrieg
cover: /images/reverse_kr/down_cover.png
---



## DownUnderCTF 2025 Reverse Engineering Writeups

![image](https://hackmd.io/_uploads/SkNuiXaLle.png)

ကျွန်တော်တို့ F$NPwn3d Team အနေနဲ့ ပြိုင်ပွဲမှာ reverse engineering challenge 6/7 ခု solve နိုင်ခဲ့ပါတယ်။  `Big thanks to my teammates who solved the two reverse engineering challenges,rocky and bilingual — awesome work!`

## rocky

```
An underdog boxer gets a once-in-a-lifetime shot at the world heavyweight title and proves his worth through sheer determination.

Regards,
jzt
```
ပထမဆုံးအနေနဲ့ Detect it Easy ဆိုတဲ့ tool ကို သုံးဘီးစစ်ကြည့်လိုက်ပါမယ်။

![image](https://hackmd.io/_uploads/BkORImaIgl.png)

packing တွေလည်းမလုပ်ထားတော့ ဒီတိုင်းဘဲ IDA နဲ့ ထပ်ဖွင့်ကြည့်ပြီး decompile ကြည့်လိုက်တော့ hashing တွေစစ်ထားတာတွေ့ရပါတယ်။

```
int __fastcall main(int argc, const char **argv, const char **envp)
{
  _BYTE v4[32]; // [rsp+0h] [rbp-60h] BYREF
  char s2[16]; // [rsp+20h] [rbp-40h] BYREF
  char s[32]; // [rsp+30h] [rbp-30h] BYREF
  _QWORD s1[2]; // [rsp+50h] [rbp-10h] BYREF

  s1[0] = 0xD2F969F60C4D9270LL;
  s1[1] = 0x1F35021256BDCA3CLL;
  printf("Enter input: ");
  fgets(s, 17, _bss_start);
  s[strcspn(s, "\n")] = 0;
  md5String(s, s2);
  if ( !memcmp(s1, s2, 0x10uLL) )
  {
    puts("Hash matched!");
    reverse_string(s, v4);
    decrypt_bytestring(s, v4);
  }
  else
  {
    puts("Hash mismatch :(");
  }
  return 0;
}
```

ဒီထဲကနေမှ md5String ဆိုတဲ့ function ကနေ တဆင့်တခြား ဒီ encryption process ထဲက တခြား functions တွေရော ကြည့်ကြည့်ရအောင်ပါ။

```
__int64 __fastcall md5String(const char *a1, _QWORD *a2)
{
  size_t v2; // rax
  __int64 result; // rax
  __int64 v4; // rdx
  _BYTE v5[88]; // [rsp+10h] [rbp-70h] BYREF
  __int64 v6; // [rsp+68h] [rbp-18h]
  __int64 v7; // [rsp+70h] [rbp-10h]

  md5Init(v5);
  v2 = strlen(a1);
  md5Update(v5, a1, v2);
  md5Finalize(v5);
  result = v6;
  v4 = v7;
  *a2 = v6;
  a2[1] = v4;
  return result;
}
__int64 __fastcall md5Init(__int64 a1)
{
  __int64 result; // rax

  *(_QWORD *)a1 = 0LL;
  *(_DWORD *)(a1 + 8) = 1732584193;
  *(_DWORD *)(a1 + 12) = -271733879;
  *(_DWORD *)(a1 + 16) = -1732584194;
  result = a1;
  *(_DWORD *)(a1 + 20) = 271733878;
  return result;
}
__int64 __fastcall md5Update(_QWORD *a1, __int64 a2, unsigned __int64 a3)
{
  unsigned int v3; // eax
  __int64 result; // rax
  _DWORD v6[17]; // [rsp+20h] [rbp-50h] BYREF
  unsigned int j; // [rsp+64h] [rbp-Ch]
  unsigned int i; // [rsp+68h] [rbp-8h]
  unsigned int v9; // [rsp+6Ch] [rbp-4h]

  v9 = *a1 & 0x3F;
  *a1 += a3;
  for ( i = 0; ; ++i )
  {
    result = i;
    if ( i >= a3 )
      break;
    v3 = v9++;
    *((_BYTE *)a1 + v3 + 24) = *(_BYTE *)(i + a2);
    if ( (v9 & 0x3F) == 0 )
    {
      for ( j = 0; j <= 0xF; ++j )
        v6[j] = *((unsigned __int8 *)a1 + 4 * j + 24) | (*((unsigned __int8 *)a1 + 4 * j + 25) << 8) | (*((unsigned __int8 *)a1 + 4 * j + 26) << 16) | (*((unsigned __int8 *)a1 + 4 * j + 27) << 24);
      md5Step(a1 + 1, v6);
      v9 = 0;
    }
  }
  return result;
}
_DWORD *__fastcall md5Finalize(__int64 a1)
{
  unsigned int v1; // eax
  _DWORD *result; // rax
  _DWORD v3[16]; // [rsp+10h] [rbp-50h] BYREF
  unsigned int v4; // [rsp+50h] [rbp-10h]
  unsigned int v5; // [rsp+54h] [rbp-Ch]
  unsigned int j; // [rsp+58h] [rbp-8h]
  unsigned int i; // [rsp+5Ch] [rbp-4h]

  v5 = *(_DWORD *)a1 & 0x3F;
  if ( v5 > 0x37 )
    v1 = 120 - v5;
  else
    v1 = 56 - v5;
  v4 = v1;
  md5Update((_QWORD *)a1, (__int64)&PADDING, v1);
  *(_QWORD *)a1 -= v4;
  for ( i = 0; i <= 0xD; ++i )
    v3[i] = *(unsigned __int8 *)(a1 + 4 * i + 24) | (*(unsigned __int8 *)(a1 + 4 * i + 1 + 24) << 8) | (*(unsigned __int8 *)(a1 + 4 * i + 2 + 24) << 16) | (*(unsigned __int8 *)(a1 + 4 * i + 3 + 24) << 24);
  v3[14] = 8 * *(_QWORD *)a1;
  v3[15] = *(_QWORD *)a1 >> 29;
  result = md5Step((int *)(a1 + 8), (__int64)v3);
  for ( j = 0; j <= 3; ++j )
  {
    *(_BYTE *)(a1 + 4 * j + 88) = *(_DWORD *)(a1 + 4LL * j + 8);
    *(_BYTE *)(a1 + 4 * j + 1 + 88) = BYTE1(*(_DWORD *)(a1 + 4LL * j + 8));
    *(_BYTE *)(a1 + 4 * j + 2 + 88) = BYTE2(*(_DWORD *)(a1 + 4LL * j + 8));
    result = (_DWORD *)a1;
    *(_BYTE *)(a1 + 4 * j + 3 + 88) = HIBYTE(*(_DWORD *)(a1 + 4LL * j + 8));
  }
  return result;
}
int __fastcall decrypt_bytestring(__int64 a1, __int64 a2)
{
  void *v2; // rsp
  __int64 v4; // [rsp+0h] [rbp-100h] BYREF
  __int64 v5; // [rsp+8h] [rbp-F8h]
  _BYTE v6[200]; // [rsp+10h] [rbp-F0h] BYREF
  void *dest; // [rsp+D8h] [rbp-28h]
  __int64 v8; // [rsp+E0h] [rbp-20h]
  size_t n; // [rsp+E8h] [rbp-18h]

  v5 = a1;
  v4 = a2;
  n = 112LL;
  v8 = 112LL;
  v2 = alloca(128LL);
  dest = &v4;
  memcpy(&v4, &precomputed, 0x70uLL);
  AES_init_ctx_iv(v6, v5, v4);
  AES_CBC_decrypt_buffer(v6, dest, n);
  *((_BYTE *)dest + n) = 0;
  return puts((const char *)dest);
}
```

> s1[0] = 0xD2F969F60C4D9270LL;
> s1[1] = 0x1F35021256BDCA3CLL;

ဒီ value နှစ်ခုကို အခြေခံဘီး md5 hash value ကို တွက်မှာပါ။ပြီးမှကျွန်တော်ထည့်တဲ့ value နဲ့ ယှဉ်ဘီး မှန်ရင် correct ဖြစ်ပီး flag ထွက်မှာပါ။ md5String ထဲက function တွေက ပုံမှန် md5 change တဲ့ function တွေပါ။ decrypt_bytestring ကတော့ မှန်ရင် flag ကို precomputed ဆိုတဲ့ 112 bytes ကနေ decrypt ပေးမှာ ဖြစ်ပါတယ်။ 

![image](https://hackmd.io/_uploads/H1-okH6Lel.png)

```
import struct

s1_0 = 0xD2F969F60C4D9270
s1_1 = 0x1F35021256BDCA3C

hash_bytes = struct.pack('<QQ', s1_0, s1_1)

expected_hash = hash_bytes.hex()

print(expected_hash)  
# Outputs: 70924d0cf669f9d23ccabd561202351f
```

ကျွန်တော်ကတော့ python ကိုသုံးဘီးတော့ expected hash ကို ထုတ်လိုက်ပါတယ်။ ပြီးမှ [crack station website](https://crackstation.net/) မှာ decrypt ကြည့်လိုက်တော့ `emergencycall911` ဆိုဘီးတော့ ရပါတယ်။
![image](https://hackmd.io/_uploads/rJL6FEpLgx.png)

ဒါဆိုရင် binary ကို run ဘီး `emergencycall911` ကို input ထည့်လိုက်တော့ flag ကို ရပါဘီ။

```
┌──(kali㉿kali)-[~/Desktop/ctf/down]
└─$ ./rocky  
Enter input: emergencycall911
Hash matched!
DUCTF{In_the_land_of_cubicles_lined_in_gray_Where_the_clock_ticks_loud_by_the_light_of_day}    
```
ဒီ challenge ရဲ့ flag ကတော့ `DUCTF{In_the_land_of_cubicles_lined_in_gray_Where_the_clock_ticks_loud_by_the_light_of_day}` ဖြစ်ပါတယ်။

## skippy

```
Skippy seems to be in a bit of trouble skipping over some sandwiched functions. Help skippy get across with a hop, skip and a jump!

Regards,
jzt
```

ပေးထားတဲ့ file ကို detect it Easy ဆိုတဲ့ tool နဲ့စစ်ကြည့်လိုက်ပါမယ်။
![image](https://hackmd.io/_uploads/B1JM-rT8gx.png)

ရိုးရိုး exe ဘဲမို့ IDA နဲ့ ဘဲ decompile လုပ်ကြည့်ပါမယ်။

```
int __fastcall main(int argc, const char **argv, const char **envp)
{
  _QWORD v4[2]; // [rsp+20h] [rbp-40h] BYREF
  char v5; // [rsp+30h] [rbp-30h]
  _QWORD v6[2]; // [rsp+40h] [rbp-20h] BYREF
  char v7; // [rsp+50h] [rbp-10h]

  _main();
  v6[0] = 0xE8BEF2E0E0D2D6E6uLL;
  v6[1] = 0xBED0E6EAC4BECAD0uLL;
  v7 = 64;
  sandwich(v6);
  v4[0] = 0xDEDEE4C2CEDCC2D6uLL;
  v4[1] = 0xDEDEDEDEDEDEDEDEuLL;
  v5 = 64;
  sandwich(v4);
  decrypt_bytestring(v6, v4);
  return 0;
}
```
array နှစ်ခုကို sandwich ဆိုတဲ့ function ကို pass ဘီး ရလာတဲ့ result ကို `decrypt_bytestring()` ဆိုတဲ့ function မှာ ယူသုံးထားပါတယ်။ ဆိုတော့ `decrypt_bytestring()` ဆိုတဲ့ function က ဘာလုပ်တာလဲဆိုတာ တစ်ချက်ကြည့်ကြည့် ရအောင်ပါ။
```
int __fastcall decrypt_bytestring(__int64 a1, __int64 a2)
{
  void *v2; // rsp
  _BYTE v4[200]; // [rsp+20h] [rbp-60h] BYREF
  char *Buffer; // [rsp+E8h] [rbp+68h]
  __int64 v6; // [rsp+F0h] [rbp+70h]
  size_t Size; // [rsp+F8h] [rbp+78h]

  Size = 96LL;
  v6 = 96LL;
  v2 = alloca(112LL);
  Buffer = v4;
  memcpy(v4, &precomputed, 0x60uLL);
  AES_init_ctx_iv(v4, a1, a2);
  AES_CBC_decrypt_buffer(v4, Buffer, Size);
  Buffer[Size] = 0;
  stone(Buffer);
  return puts(Buffer);
}
```
အပေါ်မှာ ပြောခဲ့တဲ့ variables နှစ်ခုကို key နဲ့ iv အနေနဲ့ သုံးပီး precomputed ထဲက data တွေကို AES နဲ့ decrypt လုပ်ထားတာပါ။ ဒါဆိုရင် variables နှစ်ခုကို သိရင် decrypt ပြန်လုပ်လို့ရသွားပါဘီး။

```
v6 = b'\xE6\xD6\xD2\xE0\xE0\xF2\xBE\xE8\xD0\xCA\xBE\xC4\xEA\xE6\xD0\xBE'  # v6[0], v6[1] in little-endian
v4 = b'\xD6\xC2\xDC\xCE\xC2\xE4\xDE\xDE\xDE\xDE\xDE\xDE\xDE\xDE\xDE\xDE'  # v4[0], v4[1] in little-endian


key = bytes(b >> 1 for b in v6)
iv = bytes(b >> 1 for b in v4)

print("Key (ASCII):", key.decode('ascii'))
print("IV (ASCII):", iv.decode('ascii'))

#Key (ASCII): skippy_the_bush_
#IV (ASCII): kangaroooooooooo

```
sandwich ဆိုတဲ့ function ကို analyze လုပ်ကြည့်တော့ သူက ကျွန်တော့်တို့ရဲ့ variable ကို Right-Shift လုပ်သွားတာပါ။ အာ့တော့ python နဲ့ ရေးဘီးဘဲ ရှာလိုက်တော့ `skippy_the_bush_` နဲ့ `kangaroooooooooo` ဆိုတဲ့ value နှစ်ခုရပါတယ်။
```
from Crypto.Cipher import AES

key = b"skippy_the_bush_"
iv = b"kangaroooooooooo"
ciphertext = (
    b"\xAE\x27\x24\x1B\x7F\xFD\x2C\x8B\x32\x65\xF2\x2A\xD1\xB0\x63\xF0"
    b"\x91\x5B\x6B\x95\xDC\xC0\xEE\xC1\x4D\xE2\xC5\x63\xF7\x71\x55\x94"
    b"\x00\x7D\x2B\xC7\x5E\x5D\x61\x4E\x5E\x51\x19\x0F\x4A\xD1\xFD\x21"
    b"\xC5\xC4\xB1\xAB\x89\xA4\xA7\x25\xC5\xB8\xED\x3C\xB3\x76\x30\x72"
    b"\x7B\x2D\x2A\xB7\x22\xDC\x93\x33\x26\x47\x25\xC6\xB5\xDD\xB0\x0D"
    b"\xD3\xC3\xDA\x63\x13\xF1\xE2\xF4\xDF\x51\x80\xD5\xF3\x83\x18\x43"
)

cipher = AES.new(key, AES.MODE_CBC, iv)
plaintext = cipher.decrypt(ciphertext)

if b"\0" in plaintext:
    flag = plaintext.split(b"\0")[0].decode("ascii")
else:
    padding_length = plaintext[-1]
    if 1 <= padding_length <= 16 and plaintext[-padding_length:] == bytes([padding_length] * padding_length):
        flag = plaintext[:-padding_length].decode("ascii")
    else:
        flag = plaintext.decode("ascii")

print("Flag:", flag)

#Flag: DUCTF{There_echoes_a_chorus_enending_and_wild_Laughter_and_gossip_unruly_and_piled}

```
ရလာတဲ့ key နဲ့ iv ကိုသုံးဘီး precomputed ထဲက data တွေကို decrypt လိုက်တော့ `DUCTF{There_echoes_a_chorus_enending_and_wild_Laughter_and_gossip_unruly_and_piled}` ဆိုတဲ့ flag ကို ရပါတယ်။

## godot

```
Vladimir and Estragon converse on various topics while they wait for a man named Godot. While they wait, Pozzo is on his way to the market to sell his slave, Lucky.

Regards,
jzt
```

ပေးထားတဲ့ challenge က godot ဆိုတော့ ကျွန်တော်တို့ကလည်း go dot နဲ့ ဆိုင်တဲ့ `GDRE_tools` ဆိုတဲ့ tool ကို သုံးဘီး decompile လုပ်ကြည့်ပါမယ်။

![image](https://hackmd.io/_uploads/SJrrSUa8ge.png)


`Incorrect Encryption Key` ဆိုတော့ ဒီ program က encrypt လုပ်ထားတဲ့ သဘောမျိူးဖြစ်ပါတယ်။ အာတော့ ကျွန်တော်တို့က decrypt လုပ်ရမှာဖြစ်ပါတယ်။  

![image](https://hackmd.io/_uploads/SJgluL6Lee.png)
![image](https://hackmd.io/_uploads/H1xD98TUxe.png)
![image](https://hackmd.io/_uploads/H1-zoI6Ueg.png)


ဒီ [video](https://www.youtube.com/watch?v=fWjuFmYGoSY&t=300s) ထဲမှာ ပါတဲ့ အတိုင်း encryption key ကို ရှာဘီး godot ကို decompile လုပ်လိုက်ပါတယ်။ ကျွန်တော့်မှာရတဲ့ encryption key ကတော့ `52d066de1115fc479e53fcf821715ad7db73e12df7e557833712136b4ff7529e` ဘဲဖြစ်ပါတယ်။

![image](https://hackmd.io/_uploads/HJ26o8aLxg.png)

ခုဆိုရင်တော့ decompile result ရပါဘီ။ ရလာတဲ့ result ကို godot engine ကို သုံးဘီး ဖွင့်လိုက်ပါမယ်။

![image](https://hackmd.io/_uploads/H1z02LaLgx.png)

ပြီးတော့ game ကို win သွားအောင် `@onready var isAlive = true @onready var lucky = true @onready var godot = true @onready var pozzo = true @onready var shop = true` ဆိုဘီး အကုန် True ပေးလိုက်ပါမယ်။ ပြီးတော့ camera ကို zoom out ဖြစ်သွားအောင် 
```
	var camera := get_viewport().get_camera_2d()
	if camera:
		camera.zoom = Vector2(0.8, 0.8)  # Zoom in (smaller = closer view) eeee
```
ဆိုတဲ့ code ကို edit လိုက်ပါမယ်။
![image](https://hackmd.io/_uploads/BJveZDpLxe.png)

ခုဆိုရင်တော့ E ကို နှိပ်လိုက်ရင် flag ကို ပုံထဲက အတိုင်းမြင်ရပါဘီ။
flag ကတော့ `DUCTF{THE_BOY_WILL_NEVRE_REMEMBER}`ဖြစ်ပါတယ်။

## bilingual

```
Two languages are better than one!

Regards,
FozzieBear (cybears)
```

ပထမဆုံး အနေနဲ့ ပေးထားတဲ့ code က နည်းနည်းရှုပ်နေတဲ့ အတွက် simplify version အနေနဲ့ ပြန်ရေးလိုက်ပါမယ်။
```
import ctypes
import base64
import pathlib
import sys

FLAG = 'jqsD0um75+TyJR3z0GbHwBQ+PLIdSJ+rojVscEL4IYkCOZ6+a5H1duhcq+Ub9Oa+ZWKuL703'
KEY = '68592cb91784620be98eca41f825260c'
PASSWORD = None
HELPER = None

def get_helper():
    global HELPER
    if HELPER:
        return HELPER
    dll_path = pathlib.Path(__file__).parent / 'hello.bin'
    HELPER = ctypes.cdll.LoadLibrary(str(dll_path))
    return HELPER

def decrypt_flag(password):
    flag = bytearray(base64.b64decode(FLAG))
    key = ctypes.create_string_buffer(password.encode('utf-8'))
    buffer = (ctypes.c_byte * len(flag)).from_buffer(flag)
    get_helper().Decrypt(key, len(key) - 1, buffer, len(buffer))
    return flag.decode('utf-8')

def check_one(password):
    return len(password) == 12 and get_helper().Check1(password)

def check_two(password):
    @ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_int)
    def cb(i): return ord(password[i - 3]) + 3
    return get_helper().Check2(cb)

def check_ex(password, name):
    GetIntCB = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_wchar_p)
    @GetIntCB
    def eval_cb(s):
        return int(eval(s))
    class Table(ctypes.Structure):
        _fields_ = [('E', GetIntCB)]
    func = getattr(get_helper(), name)
    print(func)
    return func(ctypes.byref(Table(E=eval_cb)))

def check_password(pw):
    global PASSWORD
    PASSWORD = pw
    return all([
        check_one(pw),
        check_two(pw),
        check_ex(pw, 'Check3'),
        check_ex(pw, 'Check4')
    ])

def main():
    if len(sys.argv) < 2:
        print("Usage: script.py <password>")
        return 1
    pw = sys.argv[1]
    if check_password(pw):
        print(f"Correct! The flag is DUCTF{{{decrypt_flag(pw)}}}")
        return 0
    else:
        print("That is not correct")
        return 1

if __name__ == '__main__':
    sys.exit(main())

```
ပေးထားတဲ့ binary ကို hello.bin အနေနဲ့ save လိုက်ပီး တခြား function တွေကိုရော ရှင်းအောင်ပြန်ရေးထားတာဖြစ်ပါတယ်။
ရှင်းရှင်းလင်းလင်းလည်းမြင်ရဘီ ဆိုတော့ check_one နဲ့ check_two ကို အရင်ကြည့်ကြပါမယ်။
```
def check_one(password):
    return len(password) == 12 and get_helper().Check1(password)
    
_BOOL8 __fastcall Check1_0(_BYTE *a1)
{
  _BOOL8 result; // rax

  result = (*a1 ^ 0x43) == 11;
  byte_180009000 = *a1 | 0x72;
  return result;
}

def check_two(password):
    @ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_int)
    def cb(i): return ord(password[i - 3]) + 3
    return get_helper().Check2(cb)
    
__int64 __fastcall Check2_0(__int64 (__fastcall *a1)(__int64))
{
  unsigned int v2; // esi
  char v3; // bp
  BOOL v4; // ebx
  char v5; // bp
  __int64 result; // rax

  v2 = 0;
  v3 = byte_180009000 ^ a1(8LL);
  v4 = v3 == 9;
  v5 = a1(9LL) + v3;
  if ( v5 == 116 )
    v2 = v4;
  result = v2;
  byte_180009001 = ~(v5 + 30);
  return result;
}
```
binary ထဲက ဟာနဲ့ python code ကို ယှဉ်ပြထားတာပါ။
check_one ကတော့ ၀င်လာတဲ့ input ထဲက first char ကို စစ်ထားတာဖြစ်ပါတယ်။
```
*a1 ^ 0x43 == 0x0B
⇒ *a1     == 0x0B ^ 0x43
⇒ *a1     == 0x48  (decimal 72)
⇒ *a1     == 'H'
```
အာတော့ first char က 'H' ဖြစ်ပီးတော့ password က 12 chars ရှိရင် pass ဖြစ်မှာပါ။
check_two ကတော့ `password[5] == 'p';password[6] == 'h'` ကို စစ်တာဖြစ်ပါတယ်။
ဒါဆို check_one  နဲ့ check_two ကို pass ဖို့ဆို `H****ph*****` ဖြစ်ရပါမယ်။
```
__int64 __fastcall Check3_0(__int64 (__fastcall **a1)(wchar_t *))
{
  _WORD *v1; // r8
  __int64 v2; // r15
  int i; // edx
  char v5; // al
  char *v6; // rdi
  int v7; // ebx
  wchar_t *v8; // rax
  bool v9; // zf
  __int64 v10; // rdx
  wchar_t v11; // cx
  wchar_t Format[12]; // [rsp+58h] [rbp-A8h] BYREF
  _OWORD v14[2]; // [rsp+70h] [rbp-90h] BYREF
  char v15; // [rsp+90h] [rbp-70h] BYREF
  __int128 v16; // [rsp+92h] [rbp-6Eh]
  __int128 v17; // [rsp+A2h] [rbp-5Eh]
  wchar_t Buffer[8]; // [rsp+110h] [rbp+10h] BYREF
  __int128 v19; // [rsp+120h] [rbp+20h]
  __int128 v20; // [rsp+130h] [rbp+30h]
  __int128 v21; // [rsp+140h] [rbp+40h]
  __int128 v22; // [rsp+150h] [rbp+50h]
  __int128 v23; // [rsp+160h] [rbp+60h]
  __int128 v24; // [rsp+170h] [rbp+70h]
  __int128 v25; // [rsp+180h] [rbp+80h]
  wchar_t v26[128]; // [rsp+190h] [rbp+90h] BYREF
  wchar_t v27[512]; // [rsp+290h] [rbp+190h] BYREF

  v1 = v14;
  memset(v14, 0, sizeof(v14));
  DWORD1(v14[0]) = 5439571;
  v2 = 0LL;
  WORD4(v14[0]) = 87;
  for ( i = 0; i < 8; ++i )
  {
    if ( i )
    {
      switch ( i )
      {
        case 1:
          v5 = LOBYTE(v14[0]) ^ 0x11;
          break;
        case 5:
          v5 = BYTE8(v14[0]) ^ 0x18;
          break;
        case 6:
          v5 = BYTE10(v14[0]) ^ 0x1D;
          break;
        case 7:
          v5 = BYTE12(v14[0]) ^ 0x16;
          break;
        default:
          goto LABEL_14;
      }
    }
    else
    {
      v5 = BYTE6(v14[0]) ^ 3;
    }
    if ( v5 )
      *v1 = v5;
LABEL_14:
    ++v1;
  }
  v6 = &v15;
  v16 = 0LL;
  v7 = 0;
  v17 = 0LL;
  do
  {
    wcscpy(Format, L"ord(%s[%d])");
    *(_OWORD *)Buffer = 0LL;
    v19 = 0LL;
    v20 = 0LL;
    v21 = 0LL;
    v22 = 0LL;
    v23 = 0LL;
    v24 = 0LL;
    v25 = 0LL;
    sub_18000108C(Buffer, Format);
    ++v7;
    *(_WORD *)v6 = (*a1)(Buffer);
    v6 += 2;
  }
  while ( v7 < 12 );
  memset(v27, 0, sizeof(v27));
  memset(v26, 0, sizeof(v26));
  sub_18000108C(v27, (wchar_t *)L"%d + 2 == %d and %d == %d and (%d - %c) == %d ");
  do
  {
    sub_18000108C(v26, (wchar_t *)L" and %d > 48 and %d < 57");
    v8 = &v26[127];
    do
    {
      v9 = v8[1] == 0;
      ++v8;
    }
    while ( !v9 );
    v10 = 0LL;
    do
    {
      v11 = v26[v10];
      v8[v10++] = v11;
    }
    while ( v11 );
    ++v2;
  }
  while ( v2 < 3 );
  return ((__int64 (__fastcall *)(wchar_t *, __int64, wchar_t *))*a1)(v27, v10, v26);
}
def check_ex(password, name):
    GetIntCB = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_wchar_p)
    @GetIntCB
    def eval_cb(s):
        print(s)
        return int(eval(s))
    class Table(ctypes.Structure):
        _fields_ = [('E', GetIntCB)]
    func = getattr(get_helper(), name)
    print(func)
    return func(ctypes.byref(Table(E=eval_cb)))
```
check_three ကတော့ ဒါတွေကို စစ်တာဖြစ်ပါတယ်။ 
```
p[7]=p[8]
p[8]+2=p[11]
p[11]-int(p[4])=p[11]
and p[7],p[8],p[11] are digit
```
 အာတော့ လောလောဆယ် known password က `H***0ph*****` ဖြစ်ပါတယ်။
check_four ကတော့ `ord(PASSWORD[1])
ord(PASSWORD[2])
ord(PASSWORD[3])
int(KEY[0:4])` ဆိုဘီး စစစ်ပါတယ်။ ကျွန်တော်တို့ကမှားနေတော့ အာ့မှာဘဲ ရပ်သွားတာပေါ့။ ပထမဆုံးအနေနဲ့ password[1],password[2],password[3] ကို မှန်အောင် bruteforce တိုက်ကြည့်ကြပါမယ်။ 
```
import ctypes
import base64
import pathlib
import sys
import sys
import itertools
import string

FLAG = 'jqsD0um75+TyJR3z0GbHwBQ+PLIdSJ+rojVscEL4IYkCOZ6+a5H1duhcq+Ub9Oa+ZWKuL703'
KEY = '68592cb91784620be98eca41f825260c'
PASSWORD = None
HELPER = None

def get_helper():
    global HELPER
    if HELPER:
        return HELPER
    dll_path = pathlib.Path(__file__).parent / 'hello.bin'
    HELPER = ctypes.cdll.LoadLibrary(str(dll_path))
    return HELPER

def decrypt_flag(password):
    flag = bytearray(base64.b64decode(FLAG))
    key = ctypes.create_string_buffer(password.encode('utf-8'))
    buffer = (ctypes.c_byte * len(flag)).from_buffer(flag)
    get_helper().Decrypt(key, len(key) - 1, buffer, len(buffer))
    return flag.decode('utf-8')

def check_one(password):
    return len(password) == 12 and get_helper().Check1(password)

def check_two(password):
    @ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_int)
    def cb(i): return ord(password[i - 3]) + 3
    return get_helper().Check2(cb)

def check_ex(password, name):
    GetIntCB = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_wchar_p)
    @GetIntCB
    def eval_cb(s):
        print(s)
        if 'int(KEY[0' in s:
            if "4" not in s:
                exit(1)
        return int(eval(s))
    class Table(ctypes.Structure):
        _fields_ = [('E', GetIntCB)]
    func = getattr(get_helper(), name)
    print(func)
    return func(ctypes.byref(Table(E=eval_cb)))

def check_password(pw):
    global PASSWORD
    PASSWORD = pw
    return all([
        check_one(pw),
        check_two(pw),
        check_ex(pw, 'Check3'),
        check_ex(pw, 'Check4')
    ])
def generate_candidates():
    # Known pattern: H _ _ _ 0 p h _ _ _ _ _ (12 chars, zero-based indices 0–11)
    base = [''] * 12
    base[0] = 'H'
    base[4] = '0'
    base[5] = 'p'
    base[6] = 'h'

    # Domain for the unknown alphabetical positions (you can adjust as needed)
    alpha_domain = string.ascii_lowercase + string.digits

    # Loop over possible triples for positions 1,2,3
    for c1, c2, c3 in itertools.product(alpha_domain, repeat=3):
        base[1], base[2], base[3] = c1, c2, c3

        # Loop over digit d for p[7] == p[8] == d and p[11] == d+2
        for d in range(0, 8):  # d up to 7 so d+2 <= 9
            base[7] = base[8] = str(d)
            base[11] = str(d + 2)

            # For the remaining unknown positions (9 and 10), you may want to brute as well
            # Here we simply fill them with a placeholder or skip
            # To brute them too, uncomment the nested loops below:

            # for x9, x10 in itertools.product(alpha_domain, repeat=2):
            #     base[9], base[10] = x9, x10
            #     yield ''.join(base)

            # If you know or fix positions 9 and 10, set them here:
            # base[9] = 'X'  # replace 'X' with actual char
            # base[10] = 'Y'

            # For now, yield with placeholders '_' for unknowns
            pwd = ''.join(base[:9] + ['_'] + ['_'] + [base[11]])
            yield pwd


def main():
    for candidate in generate_candidates():
        print(candidate)
        if check_password(candidate):
            print(f"Correct! The flag is DUCTF{{{decrypt_flag(pw)}}}")
            return 0
        else:
            print("That is not correct")


if __name__ == '__main__':
    sys.exit(main())
```
![image](https://hackmd.io/_uploads/ryxwEqp8xx.png)

bruteforece တိုက်ကြည့်ကြတော့ `ydr` ဆိုဘီးရလာပါတယ်။
 `ord(PASSWORD[9])
int(KEY[11:13])` အသစ် comparison တစ်ခုထွက်ပါဘီ။ အာ့တာကိုလည်းပထမတစ်ခေါက်ကလိုဘဲ bruteforce တိုက်ကြပါမယ်။ အာ့လိုဘဲတစ်လုံးချင်းစီတိုက်ပီး နောက်ဆုံးတော့ ` Hydr0ph11na3` ဆိုတဲ့ password ကို ရရှိပါတယ်။ အာ့တာကိုသုံးဘီး run လိုက်တာ့`DUCTF{the_problem_with_dynamic_languages_is_you_cant_c_types}` ဆိုတဲ့ flag ကို ရပါတယ်။




## SwiftPasswordManager: ClickMe

```
This password manager app has a button labeled "Flag" but it doesn't seem to be clickable...

Regards,
joseph
```
flag ဆိုတဲ့ button ကို disabled လုပ်ထားဘီး ကျွန်တော်တို့က အာ့တာကို နှိပ်ရင် flag ရမှာပါ။
![image](https://hackmd.io/_uploads/r1HULKaLle.png)

functions တွေထဲမှာ disabled ဆိုတဲ့ function တစ်ခုပါနေတာကို တွေ့ရမှာပါ
![image](https://hackmd.io/_uploads/r1clwFaIxx.png)

အာ့ကောင်ရဲ့ xref ကနေတဆင့် သွားကြည့်လိုက်တဲ့အခါမှာတော့ သူ့ကို value 1 ပေးဘီး ခေါ်ထားတာကို တွေ့ရပါတယ်။
![image](https://hackmd.io/_uploads/ByO4OY68le.png)

အာ့တော့ ကျွန်တော်တို့က ဒါကို 0 ဆိုဘီး patch လိုက်ရင် enable သဘောမျိူးဖြစ်သွားဘီး flag ရသွားမှာပါ
![image](https://hackmd.io/_uploads/BJTxttTIll.png)

အခု patch ပြီးတဲ့အခါမှာတော့ flag ကို နှိပ်လိုက်ရင် `DUCTF{just_because_the_button_is_greyed_out_doesnt_mean_you_cant_use_it}` ဆိုတဲ့ flag ကို ရရှိပါတယ်။
![image](https://hackmd.io/_uploads/B1NSYKa8xl.png)

## SwiftPasswordManager: LoadMe

```
I used the app to save a password before realising that the Load button doesn't do anything... Can you help me load my passwords? The master password is DUCTF2025!.

NOTE: This challenge uses the same handout app as "SwiftPasswordManager: ClickMe"

Regards,
joseph
```

![image](https://hackmd.io/_uploads/BJRfcYTLel.png)

သူတို့ encrypt လုပ်ထားတဲ့ file ကို ကျွန်တော်တို့က decrypt ပြန်လုပ်ပေးရမှာပါ။ အာ့တော့ သူတို့ရဲ့ encrypt လုပ်ထားပုံကို analysis လုပ်ကြည့်ရမှာပါ
သူ့ရဲ့ decompile code ကတော့ 
```
__int64 __fastcall specialized static SPMFileManager.save(entries:to:password:)(
        Swift::OpaquePointer a1,
        __int64 a2,
        __int64 a3,
        __int64 a4,
        __int64 a5)
{
  __int64 v5; // r12
  unsigned __int64 v6; // r15
  __int64 v7; // rax
  __int64 inited; // r13
  __int64 BufferUninitialized15minimumCapacitys016_ContiguousArrayB0VyxGSi_tFZ; // rbx
  __int64 v10; // r13
  unsigned __int64 v11; // rdx
  _QWORD *v12; // rax
  unsigned __int64 v13; // rdx
  __int64 v14; // rbx
  unsigned __int64 v15; // r14
  __int64 v16; // rax
  __int64 v17; // r15
  unsigned __int64 v18; // rcx
  unsigned __int64 v19; // rdx
  __int128 *v20; // rdi
  char *v21; // rsi
  __int64 v22; // rbx
  __int64 v23; // r13
  __int64 v24; // rdx
  __int64 v25; // r14
  __int64 v26; // rcx
  __int64 v27; // r15
  __int64 v28; // r8
  _QWORD *v29; // rax
  _QWORD *v30; // rax
  __int64 v31; // rbx
  unsigned __int64 v32; // r14
  __int64 v33; // r13
  unsigned __int64 v34; // r15
  __int64 *v35; // rax
  __int64 v36; // rbx
  unsigned __int64 v37; // rdx
  char *v38; // rbx
  _QWORD *v39; // rsi
  __int64 v40; // rbx
  __int64 v41; // r14
  __int64 v42; // r15
  __int64 v43; // r13
  __int64 v44; // rax
  __int64 v45; // rbx
  bool v46; // of
  __int64 v47; // r13
  __int64 v48; // r14
  __int64 v49; // r13
  __int64 v50; // rdi
  __int64 v51; // rsi
  __int64 v52; // r15
  __int64 v53; // rbx
  bool v54; // cc
  __int64 v55; // rbx
  __int64 v56; // r13
  __int64 v57; // rax
  __int64 v58; // r14
  __int64 v59; // r14
  __int64 v60; // r15
  __int64 v61; // r15
  __int64 v62; // rbx
  __int64 v63; // rbx
  unsigned __int64 v64; // r15
  __int64 v65; // rax
  unsigned __int64 v66; // rdx
  _QWORD *v67; // r14
  __int64 v68; // r15
  __int64 v69; // r13
  __int128 *v70; // rbx
  __int64 v71; // r13
  _QWORD *v72; // rdi
  char *v73; // rsi
  __int64 v74; // r15
  __int64 v75; // rbx
  __int64 v76; // r15
  char *v77; // r13
  __int64 v78; // r14
  __int64 v79; // r13
  __int64 v80; // rdx
  __int64 v81; // r15
  __int64 v82; // rax
  __int64 v83; // rax
  __int64 v84; // rdx
  __int64 v85; // rcx
  __int64 v86; // rax
  __int64 v87; // rbx
  Swift::String v88; // rdi
  __int64 v89; // rax
  __int128 v90; // xmm0
  __int64 v91; // rax
  _QWORD *v92; // rbx
  _QWORD *v93; // rax
  __int64 v94; // rdi
  __int64 v95; // rbx
  __int64 v96; // r14
  __int64 v97; // r15
  __int64 v98; // rax
  __int64 *v99; // rdx
  __int64 result; // rax
  __int64 v101; // r14
  __int64 v102; // rbx
  __int64 v103; // rdx
  __int64 v104; // rdx
  unsigned __int64 v105; // rdx
  unsigned __int64 v106; // rdx
  unsigned __int64 v107; // rdx
  __int128 v108; // rax
  __int128 v109; // kr20_16
  __int64 *v110; // rax
  __int64 v111; // r14
  __int64 v112; // rbx
  __int128 v113; // rax
  __int128 v114; // kr30_16
  __int64 *v115; // rax
  __int64 v116; // r14
  __int64 v117; // rbx
  __int128 v118; // rax
  __int128 v119; // kr40_16
  __int64 *v120; // rax
  __int64 v121; // r14
  __int64 v122; // rbx
  int v123; // eax
  __int128 v124; // rax
  __int128 v125; // kr50_16
  __int64 *v126; // rax
  __int64 v127; // r14
  __int64 v128; // r13
  __int64 v129; // rbx
  __int64 v130; // rbx
  __int64 v131; // r14
  __int128 v132; // rax
  __int128 v133; // kr60_16
  __int64 *v134; // rax
  __int64 v135; // r14
  __int64 v136; // r13
  int v137; // ebx
  __int128 v138; // rax
  __int128 v139; // kr70_16
  __int64 *v140; // rax
  __int64 v141; // r14
  __int64 v142; // r13
  __int64 v143; // rbx
  __int64 v144; // rbx
  __int64 v145; // r14
  __int128 v146; // rax
  __int128 v147; // kr80_16
  __int64 *v148; // rax
  __int64 v149; // r14
  __int64 v150; // r13
  unsigned __int64 v151; // r15
  __int64 v154; // [rsp+18h] [rbp-338h]
  __int64 v155; // [rsp+20h] [rbp-330h]
  __int64 v156; // [rsp+28h] [rbp-328h]
  __int64 v157; // [rsp+38h] [rbp-318h]
  __int64 v158; // [rsp+40h] [rbp-310h]
  __int64 v159; // [rsp+48h] [rbp-308h]
  __int64 v160; // [rsp+50h] [rbp-300h]
  __int64 v161; // [rsp+58h] [rbp-2F8h]
  unsigned __int64 v162; // [rsp+60h] [rbp-2F0h]
  __int64 v163; // [rsp+60h] [rbp-2F0h]
  unsigned __int64 v164; // [rsp+68h] [rbp-2E8h]
  unsigned __int64 v165; // [rsp+68h] [rbp-2E8h]
  __int64 v166; // [rsp+70h] [rbp-2E0h]
  __int64 v167; // [rsp+70h] [rbp-2E0h]
  __int64 v168; // [rsp+78h] [rbp-2D8h]
  __int64 v169; // [rsp+78h] [rbp-2D8h]
  unsigned __int64 v170; // [rsp+78h] [rbp-2D8h]
  unsigned __int64 v171; // [rsp+80h] [rbp-2D0h]
  __int64 v172; // [rsp+88h] [rbp-2C8h]
  __int64 v173; // [rsp+90h] [rbp-2C0h]
  __int64 v174; // [rsp+90h] [rbp-2C0h]
  __int64 v175; // [rsp+98h] [rbp-2B8h]
  __int64 v177; // [rsp+A0h] [rbp-2B0h]
  __int64 v178; // [rsp+A0h] [rbp-2B0h]
  unsigned __int64 v179; // [rsp+A0h] [rbp-2B0h]
  unsigned __int64 v181; // [rsp+A8h] [rbp-2A8h]
  __int64 v182; // [rsp+A8h] [rbp-2A8h]
  __int64 v183; // [rsp+B0h] [rbp-2A0h]
  __int64 v184; // [rsp+B0h] [rbp-2A0h]
  __int64 v185; // [rsp+B0h] [rbp-2A0h]
  char v186[24]; // [rsp+B8h] [rbp-298h] BYREF
  char v187[24]; // [rsp+D0h] [rbp-280h] BYREF
  char v188[24]; // [rsp+E8h] [rbp-268h] BYREF
  char v189; // [rsp+100h] [rbp-250h] BYREF
  char v190[24]; // [rsp+118h] [rbp-238h] BYREF
  char v191[24]; // [rsp+130h] [rbp-220h] BYREF
  char v192[24]; // [rsp+148h] [rbp-208h] BYREF
  char v193[24]; // [rsp+160h] [rbp-1F0h] BYREF
  _QWORD v194[3]; // [rsp+178h] [rbp-1D8h] BYREF
  __int64 v195; // [rsp+190h] [rbp-1C0h] BYREF
  unsigned __int64 v196; // [rsp+198h] [rbp-1B8h]
  __int64 v197; // [rsp+1A8h] [rbp-1A8h] BYREF
  unsigned __int64 v198; // [rsp+1B0h] [rbp-1A0h]
  char v199; // [rsp+1B8h] [rbp-198h] BYREF
  char v200[24]; // [rsp+1D0h] [rbp-180h] BYREF
  char v201[24]; // [rsp+1E8h] [rbp-168h] BYREF
  char v202[24]; // [rsp+200h] [rbp-150h] BYREF
  char v203[24]; // [rsp+218h] [rbp-138h] BYREF
  char v204[24]; // [rsp+230h] [rbp-120h] BYREF
  char v205[24]; // [rsp+248h] [rbp-108h] BYREF
  char v206[24]; // [rsp+260h] [rbp-F0h] BYREF
  __int128 v207; // [rsp+278h] [rbp-D8h] BYREF
  ValueMetadata *v208; // [rsp+290h] [rbp-C0h]
  _UNKNOWN **v209; // [rsp+298h] [rbp-B8h]
  char v210[80]; // [rsp+2A0h] [rbp-B0h] BYREF
  char v211[24]; // [rsp+2F0h] [rbp-60h] BYREF
  char v212[32]; // [rsp+308h] [rbp-48h] BYREF
  unsigned __int64 v213; // [rsp+328h] [rbp-28h]

  v213 = __readfsqword(0x28u);
  v6 = 0LL;
  v7 = type metadata accessor for BinaryEncoder(0LL);
  inited = swift_initStackObject(v7, v212);
  *(_QWORD *)(inited + 16) = 0LL;
  *(_QWORD *)(inited + 24) = 0xC000000000000000LL;
  BinaryEncoder.encode(_:)(a1);
  swift_beginAccess(inited + 16, v211, 0LL, 0LL);
  v159 = inited;
  v161 = *(_QWORD *)(inited + 16);
  v160 = *(_QWORD *)(inited + 24);
  ((void (*)(void))outlined copy of Data._Representation)();
  BufferUninitialized15minimumCapacitys016_ContiguousArrayB0VyxGSi_tFZ = _sSa28_allocateBufferUninitialized15minimumCapacitys016_ContiguousArrayB0VyxGSi_tFZ(
                                                                           32LL,
                                                                           &type metadata for UInt8);
  *(_QWORD *)(BufferUninitialized15minimumCapacitys016_ContiguousArrayB0VyxGSi_tFZ + 16) = 32LL;
  *(_OWORD *)(BufferUninitialized15minimumCapacitys016_ContiguousArrayB0VyxGSi_tFZ + 32) = 0LL;
  *(_OWORD *)(BufferUninitialized15minimumCapacitys016_ContiguousArrayB0VyxGSi_tFZ + 48) = 0LL;
  do
  {
    *(_QWORD *)&v207 = 0LL;
    swift_stdlib_random(&v207, 8LL);
    if ( v6 >= *(_QWORD *)(BufferUninitialized15minimumCapacitys016_ContiguousArrayB0VyxGSi_tFZ + 16) )
      BUG();
    *(_BYTE *)(BufferUninitialized15minimumCapacitys016_ContiguousArrayB0VyxGSi_tFZ + v6++ + 32) = v207;
  }
  while ( v6 != 32 );
  v10 = _s20FoundationEssentials4DataVyACxcSTRzs5UInt8V7ElementRtzlufCSayAEG_Tt0g5Tf4g_n(BufferUninitialized15minimumCapacitys016_ContiguousArrayB0VyxGSi_tFZ);
  v171 = v11;
  swift_release(BufferUninitialized15minimumCapacitys016_ContiguousArrayB0VyxGSi_tFZ);
  v12 = (_QWORD *)_sSS20FoundationEssentialsE8EncodingV4utf8ACvau();
  v14 = _sSS20FoundationEssentialsE4data5using20allowLossyConversionAA4DataVSgSSAAE8EncodingV_SbtF(*v12, 0LL, a4, a5);
  if ( (unsigned int)HIBYTE(v13) > 0xFE )
    goto LABEL_50;
  v15 = v13;
  outlined copy of Data._Representation(v14, v13);
  v16 = 43690LL;
  v166 = v14;
  v17 = v14;
  v162 = v15;
  v18 = v15;
  v19 = v171;
  v172 = v10;
  do
  {
    v173 = v16;
    v195 = v17;
    v196 = v18;
    v208 = (ValueMetadata *)&type metadata for Data;
    v209 = (_UNKNOWN **)&protocol witness table for Data;
    *(_QWORD *)&v207 = v10;
    *((_QWORD *)&v207 + 1) = v19;
    v33 = v17;
    v34 = v18;
    v35 = (__int64 *)_swift_project_boxed_opaque_existential_1(&v207);
    v36 = *v35;
    v37 = v35[1];
    v177 = v33;
    v181 = v34;
    switch ( v37 >> 62 )
    {
      case 0uLL:
        v194[0] = *v35;
        LOWORD(v194[1]) = v37;
        BYTE2(v194[1]) = BYTE2(v37);
        BYTE3(v194[1]) = BYTE3(v37);
        BYTE4(v194[1]) = BYTE4(v37);
        BYTE5(v194[1]) = BYTE5(v37);
        v38 = (char *)v194 + BYTE6(v37);
        outlined copy of Data._Representation(v33, v34);
        outlined copy of Data._Representation(v33, v34);
        outlined copy of Data._Representation(v172, v171);
        v39 = v38;
        v40 = v33;
        goto LABEL_20;
      case 1uLL:
        v52 = (int)v36;
        v53 = v36 >> 32;
        v54 = v53 < v52;
        v55 = v53 - v52;
        if ( v54 )
          BUG();
        v56 = v37 & 0x3FFFFFFFFFFFFFFFLL;
        swift_beginAccess((v37 & 0x3FFFFFFFFFFFFFFFLL) + 16, v188, 0LL, 0LL);
        v57 = v56;
        v58 = 0LL;
        if ( *(_QWORD *)(v56 + 16) )
        {
          v59 = *(_QWORD *)(v56 + 16);
          swift_beginAccess(v56 + 40, v187, 0LL, 0LL);
          v46 = __OFSUB__(v52, *(_QWORD *)(v56 + 40));
          v60 = v52 - *(_QWORD *)(v56 + 40);
          if ( v46 )
            BUG();
          v57 = v56;
          v58 = v59 + v60;
        }
        v61 = v57;
        swift_beginAccess(v57 + 24, v186, 0LL, 0LL);
        if ( *(_QWORD *)(v61 + 24) < v55 )
          v55 = *(_QWORD *)(v61 + 24);
        v62 = v58 + v55;
        if ( !v58 )
          v62 = 0LL;
        v34 = v181;
        outlined copy of Data._Representation(v177, v181);
        outlined copy of Data._Representation(v177, v181);
        outlined copy of Data._Representation(v172, v171);
        v50 = v58;
        v51 = v62;
        v40 = v177;
        goto LABEL_30;
      case 2uLL:
        v41 = v37 & 0x3FFFFFFFFFFFFFFFLL;
        swift_beginAccess(v36 + 16, v206, 0LL, 0LL);
        v42 = *(_QWORD *)(v36 + 16);
        v43 = *(_QWORD *)(v36 + 24);
        swift_beginAccess(v41 + 16, v205, 0LL, 0LL);
        v44 = v41;
        v45 = 0LL;
        if ( *(_QWORD *)(v41 + 16) )
        {
          v183 = *(_QWORD *)(v41 + 16);
          swift_beginAccess(v41 + 40, v204, 0LL, 0LL);
          if ( __OFSUB__(v42, *(_QWORD *)(v41 + 40)) )
            BUG();
          v44 = v41;
          v45 = v183 + v42 - *(_QWORD *)(v41 + 40);
        }
        v46 = __OFSUB__(v43, v42);
        v47 = v43 - v42;
        if ( v46 )
          BUG();
        v48 = v44;
        swift_beginAccess(v44 + 24, v203, 0LL, 0LL);
        if ( *(_QWORD *)(v48 + 24) < v47 )
          v47 = *(_QWORD *)(v48 + 24);
        v49 = v45 + v47;
        if ( !v45 )
          v49 = 0LL;
        v34 = v181;
        outlined copy of Data._Representation(v177, v181);
        outlined copy of Data._Representation(v177, v181);
        outlined copy of Data._Representation(v172, v171);
        v50 = v45;
        v40 = v177;
        v51 = v49;
LABEL_30:
        _s20FoundationEssentials4DataV15_RepresentationO6append10contentsOfySW_tF(v50, v51);
        break;
      case 3uLL:
        memset(v194, 0, 14);
        v40 = v33;
        outlined copy of Data._Representation(v33, v34);
        outlined copy of Data._Representation(v33, v34);
        outlined copy of Data._Representation(v172, v171);
        v39 = v194;
LABEL_20:
        _s20FoundationEssentials4DataV15_RepresentationO6append10contentsOfySW_tF(v194, v39);
        break;
    }
    _swift_destroy_boxed_opaque_existential_1(&v207);
    outlined consume of Data._Representation(v40, v34);
    v63 = v195;
    v64 = v196;
    v65 = SHA256.init()();
    v66 = v64;
    v194[0] = v65;
    v184 = v63;
    v164 = v64;
    switch ( v64 >> 62 )
    {
      case 0uLL:
        *(_QWORD *)&v207 = v63;
        WORD4(v207) = v64;
        BYTE10(v207) = BYTE2(v64);
        BYTE11(v207) = BYTE3(v64);
        BYTE12(v207) = BYTE4(v64);
        BYTE13(v207) = BYTE5(v64);
        v21 = (char *)&v207 + BYTE6(v64);
        v20 = &v207;
        break;
      case 1uLL:
        v74 = (int)v63;
        v71 = (v63 >> 32) - (int)v63;
        if ( v63 >> 32 < (int)v63 )
          BUG();
        v67 = (_QWORD *)(v66 & 0x3FFFFFFFFFFFFFFFLL);
        swift_beginAccess((v66 & 0x3FFFFFFFFFFFFFFFLL) + 16, v191, 0LL, 0LL);
        v70 = 0LL;
        if ( v67[2] )
        {
          v75 = v67[2];
          swift_beginAccess(v67 + 5, v190, 0LL, 0LL);
          v46 = __OFSUB__(v74, v67[5]);
          v76 = v74 - v67[5];
          if ( v46 )
            BUG();
          v70 = (__int128 *)(v75 + v76);
        }
        v72 = v67 + 3;
        v73 = &v189;
        goto LABEL_43;
      case 2uLL:
        v67 = (_QWORD *)(v64 & 0x3FFFFFFFFFFFFFFFLL);
        swift_beginAccess(v63 + 16, v202, 0LL, 0LL);
        v68 = *(_QWORD *)(v63 + 16);
        v69 = *(_QWORD *)(v63 + 24);
        swift_beginAccess(v67 + 2, v201, 0LL, 0LL);
        v70 = 0LL;
        if ( v67[2] )
        {
          v169 = v67[2];
          swift_beginAccess(v67 + 5, v200, 0LL, 0LL);
          if ( __OFSUB__(v68, v67[5]) )
            BUG();
          v70 = (__int128 *)(v169 + v68 - v67[5]);
        }
        v46 = __OFSUB__(v69, v68);
        v71 = v69 - v68;
        if ( v46 )
          BUG();
        v72 = v67 + 3;
        v73 = &v199;
LABEL_43:
        swift_beginAccess(v72, v73, 0LL, 0LL);
        if ( v67[3] < v71 )
          v71 = v67[3];
        v77 = (char *)v70 + v71;
        if ( !v70 )
          v77 = 0LL;
        v20 = v70;
        v21 = v77;
        break;
      case 3uLL:
        *(_QWORD *)((char *)&v207 + 6) = 0LL;
        *(_QWORD *)&v207 = 0LL;
        v20 = &v207;
        v21 = (char *)&v207;
        break;
    }
    SHA256.update(bufferPointer:)(v20, v21);
    v22 = v194[0];
    v23 = SHA256.finalize()(v194[0]);
    v25 = v24;
    v27 = v26;
    v168 = v28;
    swift_release(v22);
    outlined consume of Data._Representation(v184, v164);
    v208 = &type metadata for SHA256Digest;
    v209 = &protocol witness table for SHA256Digest;
    v29 = (_QWORD *)swift_allocObject(&unk_54A728, 48LL, 7LL);
    *(_QWORD *)&v207 = v29;
    v29[2] = v23;
    v29[3] = v25;
    v29[4] = v27;
    v29[5] = v168;
    v30 = (_QWORD *)_swift_project_boxed_opaque_existential_1(&v207);
    SHA256Digest.withUnsafeBytes<A>(_:)(
      (unsigned int)closure #1 in Data.init<A>(_:),
      0,
      *v30,
      v30[1],
      v30[2],
      v30[3],
      (__int64)&type metadata for Data._Representation);
    v31 = v195;
    v32 = v196;
    _swift_destroy_boxed_opaque_existential_1(&v207);
    outlined consume of Data._Representation(v177, v181);
    v17 = v31;
    v18 = v32;
    v16 = v173 - 1;
    v19 = v171;
    v10 = v172;
  }
  while ( v173 != 1 );
  *(_QWORD *)&v207 = v31;
  *((_QWORD *)&v207 + 1) = v32;
  v78 = SymmetricKey.init<A>(data:)(&v207, &type metadata for Data, &protocol witness table for Data, v32);
  outlined consume of Data?(v166, v162);
  v79 = AES.GCM.Nonce.init()();
  v81 = v80;
  *(_QWORD *)&v207 = v161;
  *((_QWORD *)&v207 + 1) = v160;
  v82 = lazy protocol witness table accessor for type Data and conformance Data();
  v83 = static AES.GCM.seal<A>(_:using:nonce:)(&v207, v78, v79, v81, &type metadata for Data, v82);
  if ( v5 )
  {
    outlined consume of Data._Representation(v79, v81);
    v86 = _swift_instantiateConcreteTypeFromMangledName(&demangling cache variable for type metadata for _ContiguousArrayStorage<Any>);
    v87 = swift_allocObject(v86, 64LL, 7LL);
    *(_QWORD *)(v87 + 16) = 1LL;
    *(_QWORD *)(v87 + 24) = 2LL;
    *(_QWORD *)&v207 = 0LL;
    *((_QWORD *)&v207 + 1) = 0xE000000000000000LL;
    _ss11_StringGutsV4growyySiF(20LL);
    v88._object = aEncryptionFail + 0x8000000000000000LL;
    v88._countAndFlagsBits = 0xD000000000000012LL;
    _sSS6appendyySSF(v88);
    v195 = v5;
    v89 = _swift_instantiateConcreteTypeFromMangledName(&demangling cache variable for type metadata for Error);
    _ss15_print_unlockedyyx_q_zts16TextOutputStreamR_r0_lF(
      &v195,
      &v207,
      v89,
      &type metadata for DefaultStringInterpolation,
      &protocol witness table for DefaultStringInterpolation);
    v90 = v207;
    *(_QWORD *)(v87 + 56) = &type metadata for String;
    *(_OWORD *)(v87 + 32) = v90;
    _ss5print_9separator10terminatoryypd_S2StF(v87, 32LL, 0xE100000000000000LL, 10LL, 0xE100000000000000LL);
    swift_release(v78);
    swift_release(v5);
    swift_release(v87);
    v10 = v172;
LABEL_50:
    v91 = _swift_instantiateConcreteTypeFromMangledName(&demangling cache variable for type metadata for _ContiguousArrayStorage<(String, Any)>);
    v92 = (_QWORD *)swift_initStackObject(v91, v210);
    v92[2] = 1LL;
    v92[3] = 2LL;
    v93 = (_QWORD *)_s10Foundation25NSLocalizedDescriptionKeySSvau();
    v94 = v93[1];
    v92[4] = *v93;
    v92[5] = v94;
    v92[9] = &type metadata for String;
    v92[6] = 0xD000000000000011LL;
    v92[7] = &aWarningTheAppS[96] + 0x8000000000000000LL;
    swift_bridgeObjectRetain();
    v95 = _sSD17dictionaryLiteralSDyxq_Gx_q_td_tcfCSS_ypTt0g5(v92);
    v96 = _s10Foundation7NSErrorCMa(0LL);
    swift_allocObject(v96, 48LL, 7LL);
    v97 = _s10Foundation7NSErrorC6domain4code8userInfoACSS_SiSDySSypGSgtcfc(&unk_4D5053, 0xE300000000000000LL, 1LL, v95);
    v98 = lazy protocol witness table accessor for type NSError and conformance NSError();
    swift_allocError(v96, v98, 0LL, 0LL);
    *v99 = v97;
    swift_willThrow();
    outlined consume of Data._Representation(v10, v171);
    outlined consume of Data._Representation(v161, v160);
    swift_release(v159);
    return __readfsqword(0x28u);
  }
  v158 = v78;
  v101 = v83;
  v163 = v83;
  v102 = v84;
  v154 = v84;
  v178 = v85;
  v167 = AES.GCM.SealedBox.ciphertext.getter(v83, v84, v85);
  v157 = v103;
  v155 = AES.GCM.SealedBox.tag.getter(v101, v102, v178);
  v156 = v104;
  outlined copy of Data._Representation(v79, v81);
  v175 = _s20FoundationEssentials4DataVyACxcSTRzs5UInt8V7ElementRtzlufC6Crypto3AESO3GCMO5NonceV_Tt0g5Tf4g_nTm(
           v79,
           v81,
           &type metadata for AES.GCM.Nonce,
           &protocol witness table for AES.GCM.Nonce);
  v165 = v105;
  outlined consume of Data._Representation(v79, v81);
  outlined copy of Data._Representation(v167, v157);
  v182 = _s20FoundationEssentials4DataVyACxcSTRzs5UInt8V7ElementRtzlufC6Crypto3AESO3GCMO5NonceV_Tt0g5Tf4g_nTm(
           v167,
           v157,
           &type metadata for Data,
           &protocol witness table for Data);
  v179 = v106;
  outlined consume of Data._Representation(v167, v157);
  outlined copy of Data._Representation(v155, v156);
  v174 = _s20FoundationEssentials4DataVyACxcSTRzs5UInt8V7ElementRtzlufC6Crypto3AESO3GCMO5NonceV_Tt0g5Tf4g_nTm(
           v155,
           v156,
           &type metadata for Data,
           &protocol witness table for Data);
  v170 = v107;
  outlined consume of Data._Representation(v155, v156);
  outlined consume of Data._Representation(v79, v81);
  outlined consume of Data._Representation(v167, v157);
  outlined consume of Data._Representation(v155, v156);
  outlined consume of Data._Representation(v163, v154);
  v197 = 0LL;
  v198 = 0xC000000000000000LL;
  LODWORD(v207) = 827150419;
  *(_QWORD *)&v108 = _s20FoundationEssentials4DataVyACxcSTRzs5UInt8V7ElementRtzlufCSW_Tt0g5(&v207, (char *)&v207 + 4);
  v109 = v108;
  v208 = (ValueMetadata *)&type metadata for Data;
  v209 = (_UNKNOWN **)&protocol witness table for Data;
  v207 = v108;
  v110 = (__int64 *)_swift_project_boxed_opaque_existential_1(&v207);
  v111 = *v110;
  v112 = v110[1];
  outlined copy of Data._Representation(v109, *((_QWORD *)&v109 + 1));
  specialized Data._Representation.withUnsafeBytes<A>(_:)(v111, v112, &v197);
  _swift_destroy_boxed_opaque_existential_1(&v207);
  outlined consume of Data._Representation(v109, *((_QWORD *)&v109 + 1));
  LOWORD(v207) = 1;
  *(_QWORD *)&v113 = _s20FoundationEssentials4DataVyACxcSTRzs5UInt8V7ElementRtzlufCSW_Tt0g5(&v207, (char *)&v207 + 2);
  v114 = v113;
  v208 = (ValueMetadata *)&type metadata for Data;
  v209 = (_UNKNOWN **)&protocol witness table for Data;
  v207 = v113;
  v115 = (__int64 *)_swift_project_boxed_opaque_existential_1(&v207);
  v116 = *v115;
  v117 = v115[1];
  outlined copy of Data._Representation(v114, *((_QWORD *)&v114 + 1));
  specialized Data._Representation.withUnsafeBytes<A>(_:)(v116, v117, &v197);
  _swift_destroy_boxed_opaque_existential_1(&v207);
  outlined consume of Data._Representation(v114, *((_QWORD *)&v114 + 1));
  LOWORD(v207) = 0;
  *(_QWORD *)&v118 = _s20FoundationEssentials4DataVyACxcSTRzs5UInt8V7ElementRtzlufCSW_Tt0g5(&v207, (char *)&v207 + 2);
  v119 = v118;
  v208 = (ValueMetadata *)&type metadata for Data;
  v209 = (_UNKNOWN **)&protocol witness table for Data;
  v207 = v118;
  v120 = (__int64 *)_swift_project_boxed_opaque_existential_1(&v207);
  v121 = *v120;
  v122 = v120[1];
  outlined copy of Data._Representation(v119, *((_QWORD *)&v119 + 1));
  specialized Data._Representation.withUnsafeBytes<A>(_:)(v121, v122, &v197);
  _swift_destroy_boxed_opaque_existential_1(&v207);
  outlined consume of Data._Representation(v119, *((_QWORD *)&v119 + 1));
  switch ( v171 >> 62 )
  {
    case 0uLL:
      LOWORD(v123) = BYTE6(v171);
      break;
    case 1uLL:
      v123 = HIDWORD(v172) - v172;
      if ( __OFSUB__(HIDWORD(v172), (_DWORD)v172) )
        BUG();
      if ( v123 < 0LL )
        BUG();
      if ( (unsigned __int64)v123 > 0xFFFF )
        BUG();
      return result;
    case 2uLL:
      swift_beginAccess(v172 + 16, &v195, 0LL, 0LL);
      JUMPOUT(0x3581DBLL);
    case 3uLL:
      LOWORD(v123) = 0;
      break;
  }
  LOWORD(v207) = v123;
  *(_QWORD *)&v124 = _s20FoundationEssentials4DataVyACxcSTRzs5UInt8V7ElementRtzlufCSW_Tt0g5(&v207, (char *)&v207 + 2);
  v125 = v124;
  v208 = (ValueMetadata *)&type metadata for Data;
  v209 = (_UNKNOWN **)&protocol witness table for Data;
  v207 = v124;
  v126 = (__int64 *)_swift_project_boxed_opaque_existential_1(&v207);
  v127 = *v126;
  v128 = v126[1];
  outlined copy of Data._Representation(v125, *((_QWORD *)&v125 + 1));
  specialized Data._Representation.withUnsafeBytes<A>(_:)(v127, v128, &v197);
  _swift_destroy_boxed_opaque_existential_1(&v207);
  outlined consume of Data._Representation(v125, *((_QWORD *)&v125 + 1));
  _s20FoundationEssentials4DataV6appendyyACF(v172, v171);
  outlined copy of Data._Representation(v182, v179);
  outlined copy of Data._Representation(v175, v165);
  outlined copy of Data._Representation(v174, v170);
  outlined consume of Data._Representation(v174, v170);
  outlined consume of Data._Representation(v182, v179);
  switch ( v165 >> 62 )
  {
    case 0uLL:
      outlined consume of Data._Representation(v175, v165);
      LOWORD(v129) = BYTE6(v165);
      break;
    case 1uLL:
      outlined consume of Data._Representation(v175, v165);
      LODWORD(v129) = HIDWORD(v175) - v175;
      if ( __OFSUB__(HIDWORD(v175), (_DWORD)v175) )
        BUG();
      v129 = (int)v129;
      goto LABEL_67;
    case 2uLL:
      swift_beginAccess(v175 + 16, v194, 0LL, 0LL);
      v130 = *(_QWORD *)(v175 + 24);
      v131 = *(_QWORD *)(v175 + 16);
      outlined consume of Data._Representation(v175, v165);
      v46 = __OFSUB__(v130, v131);
      v129 = v130 - v131;
      if ( v46 )
        BUG();
LABEL_67:
      if ( v129 < 0 )
        BUG();
      if ( (unsigned __int64)v129 > 0xFFFF )
        BUG();
      return result;
    case 3uLL:
      outlined consume of Data._Representation(v175, v165);
      LOWORD(v129) = 0;
      break;
  }
  LOWORD(v207) = v129;
  *(_QWORD *)&v132 = _s20FoundationEssentials4DataVyACxcSTRzs5UInt8V7ElementRtzlufCSW_Tt0g5(&v207, (char *)&v207 + 2);
  v133 = v132;
  v208 = (ValueMetadata *)&type metadata for Data;
  v209 = (_UNKNOWN **)&protocol witness table for Data;
  v207 = v132;
  v134 = (__int64 *)_swift_project_boxed_opaque_existential_1(&v207);
  v135 = *v134;
  v136 = v134[1];
  outlined copy of Data._Representation(v133, *((_QWORD *)&v133 + 1));
  specialized Data._Representation.withUnsafeBytes<A>(_:)(v135, v136, &v197);
  _swift_destroy_boxed_opaque_existential_1(&v207);
  outlined consume of Data._Representation(v133, *((_QWORD *)&v133 + 1));
  _s20FoundationEssentials4DataV6appendyyACF(v175, v165);
  outlined copy of Data._Representation(v182, v179);
  outlined copy of Data._Representation(v175, v165);
  outlined copy of Data._Representation(v174, v170);
  outlined consume of Data._Representation(v175, v165);
  outlined consume of Data._Representation(v182, v179);
  switch ( v170 >> 62 )
  {
    case 0uLL:
      JUMPOUT(0x358541LL);
    case 1uLL:
      outlined consume of Data._Representation(v174, v170);
      v137 = HIDWORD(v174) - v174;
      if ( __OFSUB__(HIDWORD(v174), (_DWORD)v174) )
        BUG();
      if ( v137 < 0LL )
        BUG();
      if ( (unsigned __int64)v137 > 0xFFFF )
        BUG();
      return result;
    case 2uLL:
      swift_beginAccess(v174 + 16, v193, 0LL, 0LL);
      JUMPOUT(0x358581LL);
    case 3uLL:
      outlined consume of Data._Representation(v174, v170);
      LOWORD(v137) = 0;
      break;
  }
  LOWORD(v207) = v137;
  *(_QWORD *)&v138 = _s20FoundationEssentials4DataVyACxcSTRzs5UInt8V7ElementRtzlufCSW_Tt0g5(&v207, (char *)&v207 + 2);
  v139 = v138;
  v208 = (ValueMetadata *)&type metadata for Data;
  v209 = (_UNKNOWN **)&protocol witness table for Data;
  v207 = v138;
  v140 = (__int64 *)_swift_project_boxed_opaque_existential_1(&v207);
  v141 = *v140;
  v142 = v140[1];
  outlined copy of Data._Representation(v139, *((_QWORD *)&v139 + 1));
  specialized Data._Representation.withUnsafeBytes<A>(_:)(v141, v142, &v197);
  _swift_destroy_boxed_opaque_existential_1(&v207);
  outlined consume of Data._Representation(v139, *((_QWORD *)&v139 + 1));
  _s20FoundationEssentials4DataV6appendyyACF(v174, v170);
  outlined copy of Data._Representation(v182, v179);
  outlined copy of Data._Representation(v175, v165);
  outlined copy of Data._Representation(v174, v170);
  outlined consume of Data._Representation(v174, v170);
  outlined consume of Data._Representation(v175, v165);
  switch ( v179 >> 62 )
  {
    case 0uLL:
      outlined consume of Data._Representation(v182, v179);
      LODWORD(v143) = BYTE6(v179);
      break;
    case 1uLL:
      outlined consume of Data._Representation(v182, v179);
      LODWORD(v143) = HIDWORD(v182) - v182;
      if ( __OFSUB__(HIDWORD(v182), (_DWORD)v182) )
        BUG();
      v143 = (int)v143;
      goto LABEL_84;
    case 2uLL:
      swift_beginAccess(v182 + 16, v192, 0LL, 0LL);
      v144 = *(_QWORD *)(v182 + 24);
      v145 = *(_QWORD *)(v182 + 16);
      outlined consume of Data._Representation(v182, v179);
      v46 = __OFSUB__(v144, v145);
      v143 = v144 - v145;
      if ( v46 )
        BUG();
LABEL_84:
      if ( v143 < 0 )
        BUG();
      if ( HIDWORD(v143) )
        BUG();
      return result;
    case 3uLL:
      outlined consume of Data._Representation(v182, v179);
      LODWORD(v143) = 0;
      break;
  }
  LODWORD(v207) = v143;
  *(_QWORD *)&v146 = _s20FoundationEssentials4DataVyACxcSTRzs5UInt8V7ElementRtzlufCSW_Tt0g5(&v207, (char *)&v207 + 4);
  v147 = v146;
  v208 = (ValueMetadata *)&type metadata for Data;
  v209 = (_UNKNOWN **)&protocol witness table for Data;
  v207 = v146;
  v148 = (__int64 *)_swift_project_boxed_opaque_existential_1(&v207);
  v149 = *v148;
  v150 = v148[1];
  outlined copy of Data._Representation(v147, *((_QWORD *)&v147 + 1));
  specialized Data._Representation.withUnsafeBytes<A>(_:)(v149, v150, &v197);
  _swift_destroy_boxed_opaque_existential_1(&v207);
  outlined consume of Data._Representation(v147, *((_QWORD *)&v147 + 1));
  _s20FoundationEssentials4DataV6appendyyACF(v182, v179);
  v185 = v197;
  v151 = v198;
  _s20FoundationEssentials4DataV5write2to7optionsyAA3URLV_AC14WritingOptionsVtKF(a2, a3, 0LL, v197, v198);
  swift_release(v158);
  outlined consume of Data._Representation(v172, v171);
  outlined consume of Data._Representation(v161, v160);
  outlined consume of Data._Representation(v182, v179);
  outlined consume of Data._Representation(v175, v165);
  outlined consume of Data._Representation(v174, v170);
  swift_release(v159);
  outlined consume of Data._Representation(v185, v151);
  return __readfsqword(0x28u);
}
```
သူရဲ့ process ကို analysis လုပ်ကြည့်လိုက်ရင်တော့ 32-bytes random number ကို generate လုပ်တယ် ပြီးတော့အာ့တာကို salt အနေနဲ့ သုံးဘီး Master key ကို hash ပြောင်းတယ်။ AES GCM tag နဲ့  AES GCM Nonce တွေကို ထုတ်တယ် ပြီးရင် အာ့တာတွေ အကုန်လုံးကို encrypted file ထဲမှာပြန်ရေးတယ်။ အာ့တာကြောင့် ကျွန်တော်တို့လုပ်ရမှာက သူ write ထားတဲ့ bytes အလိုက်ပြန်ထုတ်ဘီး decrypt ရုံပါဘဲ။
```
Started with the signature header SPM1 

2000 (0x20)  32 in decimal, it is the length of generated random number for key derivation

5F48E861D3230216A774DBB4A0EB2DA00E03CB578FC76C545433A3FE0F13D2A0 32 bytes random number for key derivation

0c00 (0x0c) 12 in decimal, it is the length of the AES GCM Nonce

followed by the nonce 56A39BC47281B9616035E692 

1000 (0x10) 16 in decimal, it is the length of the AES GCM tag

32515B011BF6E005AE4633B3708CE6E8 is the AES GCM tag

8400 (0x84)  132 in decimal is the length of the encrypted data

the last part is the encrypted data, 4A5537AFFC72008B01C38DC4A2B312B41A82A70D654D311C4F95561703BC1D61851A3F7EEFF0DFCC91CBBBB794834CE700BFCEF37A7C45D051DB38504FB7CE27194C68B64EC46215BDC775A5BBE36B0D70D5F86E9F4CC0F65A5E4C4E3F075CC4CD366F598B4982F733FBFE9475991CB32C3405792C53F89B502FCAEE153BDE1F212984AC
```
ဒါဆိုရင် ကျွန်တော်တို့က decrypt script ‌ေရးလို့ရပါဘီ။
```
from Crypto.Cipher import AES
from Crypto.Hash import SHA256

salt = bytes.fromhex('5F48E861D3230216A774DBB4A0EB2DA00E03CB578FC76C545433A3FE0F13D2A0')
master_key = b'DUCTF2025!'

def gen_key(master_key, salt):
    loop = 0xaaaa
    for i in range(loop):
        hash = master_key + salt
        master_key = SHA256.new(hash).digest()
    return master_key

key = gen_key(master_key, salt).hex()

iv = '56A39BC47281B9616035E692'
tag = '32515B011BF6E005AE4633B3708CE6E8'
ct = '4A5537AFFC72008B01C38DC4A2B312B41A82A70D654D311C4F95561703BC1D61851A3F7EEFF0DFCC91CBBBB794834CE700BFCEF37A7C45D051DB38504FB7CE27194C68B64EC46215BDC775A5BBE36B0D70D5F86E9F4CC0F65A5E4C4E3F075CC4CD366F598B4982F733FBFE9475991CB32C3405792C53F89B502FCAEE153BDE1F212984AC'

cipher = AES.new(bytes.fromhex(key), AES.MODE_GCM, bytes.fromhex(iv))
print(cipher.decrypt_and_verify(bytes.fromhex(ct), bytes.fromhex(tag)))
```
ဒါလေးကို run လိုက်ရင်တော့ `DUCTF{the_password_is_cool_but_the_flag_is_even_cooler}` ဆိုတဲ့ flag ကို ရပါတယ်။

