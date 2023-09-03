# Anti Cheat Library (UNCHEAT)
このライブラリはあなたのPEファイルを適当に難読化します。<br>
C/C++専用です。

## 使い方
build.batでいい感じにしてからuncheatディレクトリを適当な場所に置いたら
```。bash
g++ -o main.exe main.cpp -Iuncheat -L. -static -luncheat -Ofast -s -Wall -Wextra
```
という感じでコンパイルできるようになる。オプションについてもちゃんと意味はあるんやで。


## 関数の使い方

`anti_debug()`は、ある程度のデバッグから回避しようとする関数です。
```cpp
#include "uncheat/uncheat.h"

int main() {
    ucl::anti_debug();
}
```
使い方は簡単ですね。特にそれといった引数はないです。戻り値もないです。

`uc()`はコンパイル時に文字列を難読化してくれます。アルゴリズムはxorやで（）

```cpp
#include <iostream>
#include "uncheat/uncheat.h"

int main() {
    std::cout << uc("Hello, World!") << std::endl;
}
```


## 参考にしたもの
https://github.com/andrivet/ADVobfuscator/tree/master/DocCode <br>
https://www.blackhat.com/docs/eu-14/materials/eu-14-Andrivet-C-plus-plus11-Metaprogramming-Applied-To-software-Obfuscation-wp.pdf <br>
https://www.vx-underground.org/#E:/root/Papers/Windows/Evasion%20-%20Anti-debugging <br>
