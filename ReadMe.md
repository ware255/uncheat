# Anti Cheat Library (UNCHEAT)
このライブラリはあなたのPEファイルを適当に難読化します。<br>
C/C++専用です。

## 使い方
必ず最初にbuild.batを実行して、出来上がったuncheatディレクトリを適当な場所に置きます。<br>
ちなみに、想定しているディレクトリ構想は、<br>
```
project
 ├─── main.cpp
 └─── uncheat
      ├─── libuncheat.a
      └─── uncheat.h
```
こんな感じです。<br>
<br>
※コマンドは一例です。
```bash
g++ -o main.exe main.cpp -Iuncheat -L. -static -luncheat -Ofast -s -Wall -Wextra
```
コンパイルオプションについてもちゃんと意味はあります。わからないならLet's DuckDuckGo!


## 関数の使い方

### anti_debug関数
`ucl::anti_debug()`は、ある程度のデバッグから回避しようとする関数です。
```cpp
#include "uncheat/uncheat.h"

int main() {
    ucl::anti_debug();
}
```
使い方は簡単ですね。特にそれといった引数はなければ、戻り値もないです。<br>
アンチデバッグの位置は適当な場所（デバックされやすい位置）に関数を置いてみるといいかもしれません。

### uc関数(マクロ)
`uc()`はコンパイル時に文字列を難読化してくれます。アルゴリズムはxorやで（）

```cpp
#include <iostream>
#include "uncheat/uncheat.h"

int main() {
    std::cout << uc("Hello, World!") << std::endl;
}
```

### sha256関数
hashは今のところsha256しかないです。<br>
戻り値はなし。使い方は`ucl::sha256(hash化する値, hash化した物を入れる配列)`です。<br>
ちなみに、uc()で文字列をxorで暗号化しておくと全く別のhash値が出力されるのでこの場合uc()は使わない方がいいです。<br>
```cpp
#include <iostream>
#include "uncheat/uncheat.h"

int main() {
    const char *text = "Hello";

    char hash[SHA256_SIZE];
    std::cout << text << std::endl;

    ucl::sha256(text, hash);
    std::cout << hash << std::endl;
}
```

### safe_int型
私はチーター向けに新しくsafe_int型を作りました。safeって名前を付けてますが、安全性は保証しません。あくまでもチート対策向けに作った型です。使い方は下のコードを見たらだいたいわかるでしょう。
```cpp
#include <iostream>
#include <windows.h>
#include "uncheat/uncheat.h"

unsigned long randseed = 0x12345678 ^ GetTickCount();

int main() {
    ucl::safe_int hp_mob{ 9999 };
    ucl::safe_int hp{ 9999 }, ran, t;

    int n;

    while (1) {
        std::cout << "mob status" << std::endl;
        std::cout << "hp:" << hp_mob.get() << std::endl << std::endl;

        std::cout << "my status" << std::endl;
        std::cout << "hp:" << hp.get() << std::endl;

        std::cin >> n;

        switch (n) {
        case 1:
            ran = ucl::rand(randseed) % 1000;
            t = hp_mob;
            hp_mob = t - ran;
            std::cout << ran.get() << "ダメージあたえた" << std::endl;
            ran = ucl::rand(randseed) % 1000;
            t = hp;
            hp = t - ran;
            std::cout << ran.get() << "ダメージくらった" << std::endl;
            break;
        default:
            return 1;
        }

        if (hp_mob.get() <= 0) {
            std::cout << "GAME クリア！" << std::endl;
            break;
        }
        else if (hp.get() <= 0) {
            std::cout << "GAME OVER!" << std::endl;
            break;
        }

        std::cin.ignore();
        std::cin.get();
        system("cls");
    }

    std::cin.get();
    return 0;
}
```
safe_intは文字通りintです。long型でもなければdouble型でもないです。<br>
safe_int型を多用しすぎますと、プログラムの処理が重くなります。<br>理由は、内部でRSA暗号が組み込まれているからです(なるべく高速に動くように実装したが一応)。<br><br>
バグなんかありましたら、教えてください。<br><br>

## 参考にしたもの
[ADVobfuscator](https://github.com/andrivet/ADVobfuscator/tree/master/DocCode) <br>
[C++11 metaprogramming
applied to software obfuscatio](https://www.blackhat.com/docs/eu-14/materials/eu-14-Andrivet-C-plus-plus11-Metaprogramming-Applied-To-software-Obfuscation-wp.pdf) <br>
[Evasion - Anti-debugging](https://www.vx-underground.org/#E:/root/Papers/Windows/Evasion%20-%20Anti-debugging) <br>
[SHA-256](https://github.com/983/SHA-256/) <br>
[SHA-256 hash calculator](https://xorbin.com/tools/sha256-hash-calculator) <br>
[Unityでのチート対策を簡単かつ高品質に行う為の取り組み](https://www.youtube.com/watch?v=O1-a5DQxroo) <br>
[SHA-1](http://jackseven.s22.xrea.com/programming/sha1.html) <br>
[SHA1 and other hash functions online generator](http://www.sha1-online.com/) <br>
[初学者向け！RSA 暗号の基礎とシミュレーションの実装](https://cham.space/rsa/) <br>
[素数判定 in C/C++](https://qiita.com/EqualL2/items/b3c2530c458f8450d390) <br>
[skCrypter](https://github.com/skadro-official/skCrypter) <br>
[Anti-Debug: Direct debugger interaction](https://anti-debug.checkpoint.com/techniques/interactive.html) <br>
[AntiDBG](https://github.com/HackOvert/AntiDBG/) <br>
[冪乗法](https://tbasic.org/reference/old/power.html) <br>

