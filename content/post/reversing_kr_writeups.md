---
title: "reversing[.]kr writeups"
description: "reversing[.]kr ရဲ့ writeups တွေကို ကျွန်တော် ဖြေပြီးသလောက် ရေးထားတာပါ"
summary: "reversing[.]kr ရဲ့ writeups တွေကို ကျွန်တော် ဖြေပြီးသလောက် ရေးထားတာပါ"
categories: ["Writeup"]
tags: ["Reverse"]
#externalUrl: ""
date: 2025-04-27
draft: false
authors:
  - blitzkrieg
cover: /images/reverse_kr/cover.png
---

### Easy Crack

ပထမဆုံး အနေနဲ့ ကျွန်တော်က strings ကို Shfit + F12 ကို သုံးဘီးတော့ IDA ထဲမှာ ရှာလိုက်ပါတယ်
![1](https://hackmd.io/_uploads/BybHyWoBgl.png)



Strings ကို ရှာပီးသွားတော့ အာ့ထဲကမှ "Congratulation" ဆိုတဲ့စာသားကို Double Click နှိပ်ပီးတော့ Cross References ကနေ တဆင့် တကယ့် main function ရှာလိုက်ပါတယ်။ main function ကို တွေ့တဲ့အခါမှာ F5 ဆိုတဲ့ Shortcut ကို သုံးပီးတော့ Assembly ကို Decompile လုပ်လိုက်ပါတယ်။

![2](https://hackmd.io/_uploads/S1g81-iBll.png)


Decompile လုပ်ပီးတော့ ရလာတဲ့ readable ဖစ်တဲ့ code ကို သေချာဖတ်ပီး analyze လုပ်လိုက်တဲ့ အခါမှာတော့ **`Ea3yR3VERSING`** ဆိုတဲ့ flag ကို ရလာပါတယ်။


### Easy Keygen

```
ReversingKr KeygenMe


Find the Name when the Serial is 5B134977135E7D13

```


ဒီ program ကို ကျွန်တော်တို့က IDA  နဲ့ ဖွင့်ပီး အလွယ်တကူဘဲ main function ကို ရှာလိုက်ပါတယ်


![3](https://hackmd.io/_uploads/rkJwybsBxx.png)


main function ရဲ့  Decompile code ကို သေချာဖတ်ကြည့်လိုက်တဲ့အခါမှာတော့ xor encryption ကို သုံးထားတာကို တွေ့ရပါတယ်။ xor encryption ရဲ့ သ‌ဘောတရားက key သိရင် ပြန်ဖော်လို့ ရတာမို့ ကျွန်တော်ကတော့ python နဲ့ script ရေးပီးတော့ solve ထားပါတယ်။



```
#!/usr/bin/env python3
import re

def recover_name(serial: str) -> str:
    hex_str = re.sub(r'[^0-9A-Fa-f]', '', serial)
    
    keys = [16, ord(' '), ord('0')]
    
    name_chars = []
    for idx in range(0, len(hex_str), 2):
        byte = int(hex_str[idx:idx+2], 16)
        key = keys[(idx // 2) % 3]
        name_chars.append(chr(byte ^ key))
    
    return ''.join(name_chars)

if __name__ == "__main__":
    s = input("Enter serial: ")
    try:
        original_name = recover_name(s)
        print("Recovered Name:", original_name)
    except ValueError as e:
        print("Error:", e)
```


ဒါကို run လိုက်ပီးတော့ expected serial ဖြစ်တဲ့ **5B134977135E7D13** ကိုထည့်လိုက်ရင်တေ့ **`K3yg3nm3`** ဆိုတဲ့ flag ကို ရပါတယ်။

### Easy Unpack 


```
ReversingKr UnpackMe


Find the OEP

ex) 00401000

```


ဒီ challenge မှာတော့ သူတို့ ပေးထားတဲ့ exe က pack လုပ်ထားတာဖြစ်ပြီး ကျွန်တော်တို့ကို ***original entry point(OEP)*** ကို ရှာခိုင်းထားတာ ဖြစ်ပါတယ်။


```
Entry point ဆိုတာကတော့ program တစ်ခုရဲ့ အစ ဖြစ်ပီးတော့ packed လုပ်လိုက်တဲ့ အချိန်မာတော့ မူလ entry point value တွေက  change သွားတတ်ကြပါတယ်။
```


ဆိုတော့ ပထမဆုံးအနေနဲ့ Detect it Easy ဆိုတဲ့ tool ကို သုံးဘီးတော့ စစ် ကြည့်ပါမယ်။


![image](https://hackmd.io/_uploads/BkRZrF6Hle.png)


![image](https://hackmd.io/_uploads/S19dHYpBex.png)

စစ်ကြည့်လိုက်တဲ့ result တွေအရတော့ program က import က ၃ ခု ဘဲရှိတဲ့ အတွက် packed လုပ်ထားတယ်ဆိုတာ suspicious ဖြစ်စရာကောင်းပါတယ်။

IDA နဲ့ program ကို ဖွင့်လိုက်ပီး ကြည့်ကြည့်တဲ့ အခါမာတော့ jump ခုန်ထားတာတစ်ခု ကို တွေ့ရပါတယ်။


![image](https://hackmd.io/_uploads/SJTKDYaBeg.png)


![image](https://hackmd.io/_uploads/SJ65vY6Blg.png)

အာ့တာက packed လုပ်ထားတဲ့ exe ရဲ့ OEP လို့ထင်တဲ့အတွက် x32dbg နဲ့ debug လုပ်ကြည့်ပါမယ်။ ဒီနေရာမာ exe က 32 bits ဖြစ်တဲ့အတွက် x32dbg ကို သုံးတာဖြစ်ပါတယ်။

`bp Easy_UnpackMe.exe+0xA1FB`

***jump*** လုပ်သွားတဲ့ address ကို break point ထားပီး run ကြည့်ပါမယ်။


![image](https://hackmd.io/_uploads/rk4RKYpSex.png)


ဆိုတော့ ဒါက  original entry point ဆိုဘီး ခန့်မှန်းမိလိုက်ပါဘီ ။ ကျွန်တော်ကတော့ `scylla` ဆိုတဲ့ tool ကို သုံးပီး dump မာဖြစ်ပါတယ်။  `IAT Auto Search ` ကို သုံးမယ် ပြီးရင် `imports` တွေကို ရှာမယ် `dump` ကို နှိပ်မယ် ဒါပါဘဲ။

![image](https://hackmd.io/_uploads/HkycqFTrex.png)

ရလာတဲ့ program ကို ida နဲ့ ကြည့်ကြည့်ရင်တော့ unpacked version ဖြစ်တဲ့အတွက် analyze လုပ်လို့ရသွားပါဘီ။

![image](https://hackmd.io/_uploads/SJTFsFTHle.png)

ဒီ challenge ရဲ့ flag ကတော့  `0x401150` ဖြစ်ပါတယ်။

### Music Player

```
This MP3 Player is limited to 1 minutes.
You have to play more than one minute.

There are exist several 1-minute-check-routine.
After bypassing every check routine, you will see the perfect flag.

```
ဒီ challenge မှာကတော့ သူက mp3 တွေကို ၁မိနစ် ဘဲရအောင် လုပ်ထားဘီး အာ့တာကို bypass ရမာဖြစ်ပါတယ်။

ပထမဆုံး ida ကိုသုံးဘီး program ကို ဖွင့်ကြည့်လိုက်ပါမယ် ရှာလို့ကောင်းမယ့်ဟာလေးတွေထဲကမှ ကျွန်တော်ကတော့ imports ထဲက rtcMsgBox ဆိုတဲ့ကောင်ရဲ့ cross references ကနေဘဲ ရှာလိုက်ပါတယ်။ 

![image](https://hackmd.io/_uploads/HkQ3moTreg.png)

ဒီ function ကို ခေါ်ထားတဲ့ call တွေ ထဲကမှ ပထမဆုံး call မှာ သူ့ဆီမရောက်ခင်မှာ condition စစ်ထားတာကို တွေ့ရပါတယ်။ condition ကလည်း 6000 ဖြစ်နေတော့ စဉ်းစားကြည့်မယ်ဆိုရင်  60000ms = 1p ဖြစ်တဲ့အတွက် ၁မိနစ် ကို စစ်ထားတာပါ

![image](https://hackmd.io/_uploads/ry5SUopBee.png)

အာ့တော့ ကျွန်တော်တို့က ဒါကို patch ရမယ်ပေါ့ ဘယ်လို patch မလဲဆို ကျွန်တော်ကတော့ value ကိုဘဲ edit လိုက်ပါတယ်။ အာ့လိုမဟုတ်ဘဲ jl ကို jump ပြောင်းတာမျိုး ဖြစ်ဖြစ် nop ထည့်တာဖြစ်ဖြစ်ဆိုလဲ အဆင်ပြေမာပါ။

![image](https://hackmd.io/_uploads/HkJG_s6Beg.png)

အာ့တာကို patch ပီး ထပ် run ကြည့်တော့ bypass တော့ဖြစ်သွားပေမယ့် နောက် error တစ်ခုထပ်တက်ပါတယ်။ 

![image](https://hackmd.io/_uploads/rkXrYspHlg.png)

ဘာလို့တက်တာလည်းဆိုတာကို x32dbg နဲ့ debug ကြည့်ရအောင်ပါ ပုံကို ကြည့်ကြည့်ရင်တော့ xdbg call stack ကနေပီးတော့ error ကို trace လိုက်ကြည့်တဲ့အခါ **`[<vbaHresultCheckObj>]`** ဆိုတဲ့ function call ကြောင့်ဆိုတာ သိရပါတယ်။

![image](https://hackmd.io/_uploads/B15Fco6rex.png)

![image](https://hackmd.io/_uploads/SkrFsjpree.png)

အာ့တော့ function call မဖြစ်အောင် patch ဖို့အတွက် jge နေရာမှာ jump ဆိုဘီးတော့ patch လိုက်ပါမယ်။ အ‌‌ရှေ့က error တက်တဲ့ function call ကို ခေါ်တာကလည်း jge ကြောင့် function jump မဖြစ်လို့ ဖြစ်ပါတယ်။

![image](https://hackmd.io/_uploads/SJ722o6Hxx.png)


![image](https://hackmd.io/_uploads/SyWZfTaSll.png)

patch ပီးတော့ run လိုက်တဲ့အခါမှာတော့ flag ကို ရဘီ ဖြစ်ပါတယ်။

![image](https://hackmd.io/_uploads/S1bkzapSlg.png)

ဒီ challenge ရဲ့ flag ကတော့ `LIstenCare` ဖြစ်ပါတယ်။

### Easy ELF

ဒီ challenge လေးကတော့ linux binary ကို reverse engineering ပြုလုပ်ရမှာ ဖြစ်ပါတယ်။
ပထမဆုံးအနေနဲ့ ida နဲ့ ဖွင့်ဘီး diassamble လုပ်ကြည့်တဲ့အခါ main function ကို တွေ့ရပါတယ်။
```
int main()
{
  write(1, "Reversing.Kr Easy ELF\n\n", 0x17u);
  sub_8048434();
  if ( sub_8048451() == 1 )
    sub_80484F7();
  else
    write(1, "Wrong\n", 6u);
  return 0;
}
```
code ကို ဖတ်ကြည့်လိုက်တော့ sub_8048451 ဟာ တစ်ခုခုကို စစ်ထားတာနဲ့တူတဲ့အတွက် ထပ်ဆင့် disassemble လုပ်ပီး ကြည့်ကြည့်ပါမယ်။
```
_BOOL4 sub_8048451()
{
  if ( byte_804A021 != 49 )
    return 0;
  byte_804A020 ^= 0x34u;
  byte_804A022 ^= 0x32u;
  byte_804A023 ^= 0x88u;
  if ( byte_804A024 != 88 )
    return 0;
  if ( byte_804A025 )
    return 0;
  if ( byte_804A022 != 124 )
    return 0;
  if ( byte_804A020 == 120 )
    return byte_804A023 == -35;
  return 0;
}
```

condition ငါးခုကို နှိုင်းယှဉ်ပီး password ကို စစ်ထားတာဖြစ်တဲ့အတွက် ကျွန်တော်ကတော့ python3 နဲ့ script ပြန်ရေးဘီး solve ထားပါတယ်။
```
#!/usr/bin/env python3

def get_password() -> str:
    vals = [
        120 ^ 0x34,  # byte 0
        49,          # byte 1
        124 ^ 0x32,  # byte 2
        221 ^ 0x88,  # byte 3
        88           # byte 4
    ]
    return bytes(vals).decode('ascii')

if __name__ == "__main__":
    print(get_password())

```
ခု challenge ရဲ့ flag ကတော့ ခု python program ကို run လိုက်ရင် ရလာမယ့် `L1NUX` ဖြစ်ပါတယ်။


