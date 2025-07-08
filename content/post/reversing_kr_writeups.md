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

ပထမဆုံး အနေနဲ့ ကျွန်တော်က strings ကို Shfit + F12 ကို သုံးဘီးတော့ IDA pro ထဲမှာ ရှာလိုက်ပါတယ်
![1](https://hackmd.io/_uploads/BybHyWoBgl.png)



Strings ကို ရှာပီးသွားတော့ အာ့ထဲကမှ "Congratulation" ဆိုတဲ့စာသားကို Double Click နှိပ်ပီးတော့ Cross References ကနေ တဆင့် တကယ့် main program ရှာလိုက်ပါတယ်။ main program ကို တွေ့တဲ့အခါမှာ F5 ဆိုတဲ့ Shortcut ကို သုံးပီးတော့ Assembly ကို Decompile လုပ်လိုက်ပါတယ်။

![2](https://hackmd.io/_uploads/S1g81-iBll.png)


Decompile လုပ်ပီးတော့ ရလာတဲ့ readable ဖစ်တဲ့ code ကို သေချာဖတ်ပီး analyze လုပ်လိုက်တဲ့ အခါမှာတော့ **`Ea3yR3VERSING`** ဆိုတဲ့ flag ကို ရလာပါတယ်။


### Easy Keygen

ဒီ program ကို ကျွန်တော်တို့က IDA pro နဲ့ ဖွင့်ပီး အလွယ်တကူဘဲ main function ကို ရှာလိုက်ပါတယ်

![3](https://hackmd.io/_uploads/rkJwybsBxx.png)


main function ရဲ့  Decompile code ကို သေချာဖတ်ကြည့်လိုက်တဲ့အခါမှာတော့ xor encryption ကို သုံးထားတာကို တွေ့ရပါတယ်။ xor encryption ရဲ့ သ‌ဘောတရားက key သိရင် ပြန်ဖော်လို့ ရတာမို့ ကျွန်တော်တို့က python နဲ့ script ရေးပီးတော့ solve ထားပါတယ်။

```
#!/usr/bin/env python3

def reverse_serial(serial: str) -> str:
    pattern = [0x10, 0x20, 0x30]

    # Recover original characters
    name_chars = []
    for i, b in enumerate(byte_vals):
        key = pattern[i % len(pattern)]
        name_chars.append(chr(b ^ key))

    return ''.join(name_chars)


def main():
    serial = input("Enter serial: ").strip()
    try:
        name = reverse_serial(serial)
        print(f"Recovered name: {name}")
    except ValueError as e:
        print(f"Error: {e}")


if __name__ == '__main__':
    main()

```
ဒါကို run လိုက်မယ်ဆိုရင်တော့ **`K3yg3nm3`** ဆိုတဲ့ flag ကို ရပါတယ်။




