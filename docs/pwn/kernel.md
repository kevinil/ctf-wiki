# 内核 Pwn 入门

关键词：内核 kernel pwn bzImage initramfs cpio run.sh qemu kallsyms commit_creds prepare_kernel_cred swapgs_restore_regs_and_return_to_usermode SMEP SMAP KASLR KPTI native_write_cr4 modprobe_path core_pattern 提权 .ko pwn

## ① 识别指纹

- 附件是四件套：`bzImage`、`initramfs.cpio` / `rootfs.cpio.gz`、`run.sh` / `start.sh`、`*.ko`；有时再给 `vmlinux`、`System.map`
- `file bzImage` 显示 `Linux kernel x86 boot executable bzImage`；`file *.ko` 显示 `ELF ... relocatable`
- `run.sh` 里有 `qemu-system-x86_64 -kernel bzImage -initrd ... -append ... -nographic`
- 题干要求“拿到 root”“读取 `/flag`”，并说明有一个 `/dev/xxx` 或 `/proc/xxx` 接口
- 附件里带 `core.cpio`、`rootfs.cpio`、`exp.c` 模板，或者带一个明显有漏洞的内核模块
- 题目名带 `kernel` / `core` / `babykernel` / `kernelpwn`
- 不是普通 `nc host port`，而是先本地起 QEMU，再用 gdb 远程调试
- `checksec` 对 `bzImage` 不适用；对 `.ko` 只看架构、RELRO、NX、Canary，内核保护要看 `run.sh` 与 `/proc/cmdline`

## ② 考什么

- 题目结构：内核镜像 + initramfs + 启动脚本 + 漏洞模块
- 解包 cpio、读 `/init` 或 `rcS`、必要时重新打包
- QEMU 启动参数、`-s -S`、gdb 连接 `vmlinux`
- 模块交互：`open` / `ioctl` / `read` / `write` / `mmap`
- 内核内存：`kmalloc` / `kfree`、slab、没有 glibc 堆
- 符号获取：`/proc/kallsyms`、`/tmp/kallsyms`、`vmlinux`、`System.map`
- KASLR、SMEP、SMAP、KPTI 的识别与组合
- `commit_creds(prepare_kernel_cred(0))` 提权
- 返回用户态：保存 `cs / ss / rflags / rsp / rip`，`swapgs; iretq`，或 `swapgs_restore_regs_and_return_to_usermode`
- `modprobe_path` / `core_pattern` / `poweroff_cmd` 数据型利用
- `native_write_cr4` 关 SMEP / SMAP
- 栈溢出、堆溢出、UAF、OOB、double fetch
- 内核栈通常只有 16KB（配置不同会变），ROP 链长度受限
- `copy_from_user` / `copy_to_user`、用户态指针与内核态指针的区别

## ③ 判断流程

### ③-1 子类型分流

1. **附件是不是 `bzImage` + initramfs + `run.sh`** → 是，跳到第 2 条；只有 `.ko` 没有内核镜像 → 回 [题型总表](/map) 重新确认附件；是普通 ELF → 回 [栈溢出基础](/pwn/stack-basic)
2. **解包 initramfs** → `cpio -idmv < initramfs.cpio`，gz 先 `zcat`；成功，跳到第 3 条；解包失败，改用 `binwalk -e` 或 `7z`，仍失败，检查是不是 tar / cpio newc，跳到第 3 条
3. **读 `/init` 或 `/etc/init.d/rcS`** → 找到 `insmod *.ko`、`chmod 666 /dev/*`、flag 路径、启动用户 → 跳到第 4 条；找不到模块，执行 `find . -name '*.ko'`，跳到第 4 条
4. **读 `run.sh`** → 记录 `-append` 里的 `kaslr` / `nokaslr`、`-cpu` 的 `+smep` / `+smap`、`pti=on/off`、`oops=panic`，以及 `-m` / `-smp` → 跳到第 5 条
5. **启动 QEMU 并确认身份** → `./run.sh` 后 `id` 不是 root，目标设备存在且可读写，跳到第 6 条；起不来，检查 qemu 版本与镜像路径，回到第 4 条
6. **看符号可见性** → `cat /proc/kallsyms | head`、`ls -l /tmp/kallsyms`、`cat /proc/sys/kernel/kptr_restrict`；能拿到 `commit_creds` / `prepare_kernel_cred` / `modprobe_path`，跳到第 7 条；全是 0，需要泄露或本地 `nokaslr` 调试，跳到第 7 条
7. **逆模块找 bug** → IDA / Ghidra 看 `file_operations` 的 `ioctl` / `read` / `write` / `mmap`、`copy_from_user` 长度、全局数组、锁 → 栈溢出，转 ③-2 A 组第 1 条；堆 / UAF / OOB，转 B 组第 1 条；任意写，转 C 组第 1 条；都不属于，回到第 7 条换模块或设备
8. **以上都不成立** → 回第 1 条，换一个模块 / 设备节点；仍无 → 这题不是内核入门，回 [题型总表](/map)

### ③-2 成本排序链

**A. 内核栈溢出**

1. **确认溢出点** → `copy_from_user` / `qmemcpy` / `memcpy` 的长度可控，且能覆盖到返回地址 → 进入第 2 条；长度有上界且不可绕过，转 B 组第 1 条
2. **记录保护状态** → 看模块是否带 canary、`run.sh` 是否开 SMEP / SMAP / KPTI → canary 存在，跳到第 7 条；无 canary，跳到第 3 条
3. **量偏移** → gdb 在拷贝函数返回后看 `rsp` 与返回地址的距离；本地用 `nokaslr` 方便断点 → 得到偏移，跳到第 4 条；断不下来，改用 `vmlinux` 符号 + 源码行号，回到第 3 条
4. **准备符号与 gadget** → 从 `/tmp/kallsyms` 取 `commit_creds` / `prepare_kernel_cred`；从 `vmlinux` 取 `pop rdi; ret`、`mov rdi, rax; ...`、`swapgs` / `iretq` 相关 gadget → 齐了，跳到第 5 条；缺 gadget，换 `vmlinux` 里的等价组合，回到第 4 条
5. **构造提权链** → `pop rdi; ret` + `0` 调 `prepare_kernel_cred`，把 `rax` 移到 `rdi` 调 `commit_creds` → 进入第 6 条
6. **返回用户态** → 用户态提前保存 `cs / ss / rflags / rsp`；ROP 末尾用 `swapgs_restore_regs_and_return_to_usermode` 或 `swapgs; iretq`，栈上依次放 `RIP / CS / RFLAGS / RSP / SS` → 结束
7. **泄露 canary** → 用模块自带的读原语 / 越界读把 canary 读出来，payload 中原样填回 → 回到第 3 条
8. **SMEP / SMAP 开着** → 不能 ret2usr；只能在内核 ROP 里完成提权；需要访问用户内存时，先用 `native_write_cr4` 清 CR4 对应位（SMEP 是 bit20，SMAP 是 bit21）→ 回到第 4 条；保护没开，用 ret2usr 执行提权函数后跳到第 6 条
9. **KPTI 开着** → 不能直接 `swapgs; iretq`，必须走 `swapgs_restore_regs_and_return_to_usermode` 的 trampoline，并按版本跳过开头的 `mov rdi, rsp` → 回到第 6 条
10. **以上都不成立** → 转 B 组或 C 组；仍无 → 回 ③-1 第 7 条

**B. 堆 / UAF / OOB**

1. **确认对象生命周期** → `kmalloc` 后 `kfree` 但指针不清空、引用计数错、free 后仍可读写 → **UAF**，跳到第 2 条；越界读写相邻对象 → **OOB**，跳到第 3 条
2. **UAF 占位** → 用同 size 的对象重占：`tty_struct`、`seq_operations`、`msg_msg`、`pipe_buffer` 等 → 能泄露内核指针或劫持函数指针，跳到第 4 条；占不上，换对象或调整 slab 布局，回到第 2 条
3. **OOB 找相邻对象** → 同 cache 的对象在 slab 中相邻，先越界读泄露，再越界写改函数指针 / `cred` → 跳到第 4 条；相邻对象不可控，换申请顺序，回到第 3 条
4. **拿到能力** → 有控制流：回到 A 组第 4 条做内核 ROP；有任意写：转 C 组第 1 条；能定位当前进程的 `cred`：跳到第 5 条
5. **改 cred** → 找到 `task_struct->cred`，把 `uid / gid / euid / egid / ...` 置 0；不需要 ROP → 结束
6. **以上都不成立** → 回第 1 条，换对象 / 换设备；仍无 → 回 ③-1 第 7 条

**C. 任意写与 modprobe_path**

1. **确认任意写** → 模块的 `write` / `ioctl` 能写到指定内核地址，或越界写完全可控 → 进入第 2 条；只有任意读，用读泄露后转 A / B 组
2. **取 `modprobe_path` 地址** → `grep ' modprobe_path$' /proc/kallsyms`，或 `/tmp/kallsyms`、`vmlinux` 的符号表；KASLR 下每次启动地址不同 → 拿到当次地址，跳到第 3 条；拿不到，先泄露内核基址，回到第 2 条
3. **覆写字符串** → 把 `modprobe_path` 改成 `/tmp/x`，长度不超过原字符串，剩余字节补 `\x00` → 跳到第 4 条
4. **准备 `/tmp/x`** → 内容 `#!/bin/sh` 加 `chmod 777 /flag` 或 `cat /flag > /tmp/out`，并 `chmod +x` → 跳到第 5 条
5. **触发** → 创建内容为 `\xff\xff\xff\xff` 的非法格式文件并 `execve`；内核匹配不到 binfmt 时调用 `request_module`，以 root 执行 `modprobe_path` → 读取 flag，结束
6. **`modprobe_path` 改不动** → `CONFIG_STATIC_USERMODEHELPER` 固定了 helper，或目标地址只读 → 改 `core_pattern` / `poweroff_cmd`，或回到 A 组做 ROP
7. **只能 4 字节写** → 分多次写 `/tmp/x`，注意字符串结尾的 `\x00` → 回到第 3 条
8. **以上都不成立** → 回 ③-1 第 7 条，重新确认漏洞原语

## ④ 工具与命令

```bash
file bzImage initramfs.cpio run.sh *.ko
ls -la
```

```bash
# 解包 initramfs（cpio，不是 tar）
mkdir rootfs && cd rootfs
cpio -idmv --no-absolute-filenames < ../initramfs.cpio
# gz 压缩的版本
zcat ../initramfs.cpio.gz | cpio -idmv --no-absolute-filenames
find . -name '*.ko' -o -name init -o -name rcS
```

```bash
# 改完 init 后重新打包（可选）
find . | cpio -o -H newc | gzip > ../initramfs.cpio.gz
```

```bash
# 启动；若脚本不转发 -s，就复制一份脚本加参数
./run.sh
qemu-system-x86_64 -kernel bzImage -initrd initramfs.cpio \
  -append "console=ttyS0 root=/dev/ram rw" -nographic -s -S
```

```bash
# VM 内：符号、模块、保护
id
cat /proc/cmdline
cat /proc/sys/kernel/kptr_restrict
cat /proc/kallsyms | grep -E ' (commit_creds|prepare_kernel_cred|modprobe_path)$'
cat /proc/modules
ls -l /dev/<模块设备>
cat /sys/module/<模块名>/sections/.text
```

```bash
# 宿主机：vmlinux、gadget、gdb
extract-vmlinux bzImage > vmlinux
ROPgadget --binary vmlinux --only 'pop|ret' | grep 'pop rdi'
gdb vmlinux -ex 'target remote :1234'
```

```bash
# 编译静态 exp 并传进 VM
musl-gcc -static -O2 exp.c -o exp
base64 -w0 exp
# VM 内：echo <base64> | base64 -d > /tmp/exp && chmod +x /tmp/exp
```

## ⑤ 常见坑

| 现象 | 实际原因 | 正确应对 |
|---|---|---|
| `bzImage` 解不开 | 它是压缩的内核镜像，不是普通压缩包 | `extract-vmlinux bzImage > vmlinux` 或 `binwalk -e` |
| `cpio` 解包报格式错 | initramfs 是 cpio newc，不是 tar | 用 `cpio -idmv`；gz 先 `zcat` |
| 改完 init 重新打包后启动失败 | 打包顺序 / 权限 / 设备节点不对 | 用 `find` 列出文件后交给 `cpio -o -H newc`，保留原有权限 |
| `run.sh` 起不来 | 脚本用相对路径，或 qemu 版本不匹配 | 在题目目录执行，检查 qemu 参数与镜像名 |
| 本地能起、远程不能 | CPU 特性不同（SMEP / SMAP）或内核版本不同 | 以附件 `run.sh` 为准，远程优先 |
| `/proc/kallsyms` 全是 0 | `kptr_restrict` 限制，当前用户非 root | 读 `/tmp/kallsyms`、leak 内核指针，或本地加 `nokaslr` 调试 |
| 抄了别的题的 `commit_creds` 偏移 | 内核版本 / 配置不同，符号偏移不同 | 用本题 `vmlinux` 或 `/proc/kallsyms` 重新取 |
| `swapgs_restore...` 跳过去就崩 | 偏移差几条指令，或没跳过 `mov rdi, rsp` | 在 `vmlinux` 里反汇编确认入口，按版本加偏移 |
| 返回用户态时 triple fault | iretq 帧顺序错，或忘了 `swapgs` | 顺序是 `RIP / CS / RFLAGS / RSP / SS` |
| SMEP 开着还 ret2usr | 内核不能执行用户页 | 用内核 ROP，或 `native_write_cr4` 清 CR4 bit20 |
| SMAP 开着传用户指针 | 内核不能直接访问用户内存 | 先把数据复制到内核缓冲区，或清 CR4 bit21 |
| 一次失败 QEMU 就重启 | `oops=panic` / `panic_on_warn` | 调试时先关掉这两个参数 |
| ROP 链太长踩坏内核栈 | 内核栈通常 16KB，且栈上有其他数据 | 把链放 `.bss`，用栈迁移或分段执行 |
| `modprobe_path` 改了不触发 | 非法文件没执行权限，或 `CONFIG_STATIC_USERMODEHELPER` 固定了 helper | 检查配置与文件权限，改用 `core_pattern` |
| `ioctl` 没反应 | 命令号或结构体大小与模块不一致 | 按 `_IOW` / `_IOR` 宏还原命令号与结构体 |

## ⑥ 例题

**题目**：强网杯 2018 `core`
**来源**：2018 强网杯线上赛；附件为 `bzImage`、`core.cpio`、`start.sh`、`core.ko`、`vmlinux`，BUUCTF 有复现

**题干**：启动 QEMU 后以普通用户进入系统，`/proc/core` 提供 ioctl 接口，目标是读取 `/flag`。

**关键观察**：
- `start.sh` 用 `qemu-system-x86_64 -kernel bzImage -initrd core.cpio -append "console=ttyS0 ... kaslr"` 启动；原版开启 KASLR，没有开 SMEP / SMAP
- `core.ko` 的 ioctl：`0x6677889B` 读 64 字节、`0x6677889C` 设置全局 `off`、`0x6677889A` 按长度拷贝
- `core_copy_func` 用有符号比较 `len > 63`，随后把 `len` 截成 `unsigned __int16` 交给 `qmemcpy`；传负值可以绕过检查
- 模块栈上的 canary 位于 `name + 0x40`；设置 `off = 0x40` 后，`core_read` 读出的前 8 字节就是 canary
- init 脚本把 `/proc/kallsyms` 复制到 `/tmp/kallsyms`，普通用户可读，`commit_creds` / `prepare_kernel_cred` 直接可取

**走了哪条链**：③-1 第 1–6 条（识别附件、解包、读 init、读 `run.sh`、启动、取符号）→ 第 7 条（栈溢出）→ ③-2 A 组第 1 条（确认长度可控）→ 第 2 条（记录 canary / 保护）→ 第 7 条（泄露 canary）→ 第 3–6 条（量偏移、ROP、`commit_creds`、返回用户态）。

**命令与输出**：

```text
$ file bzImage core.ko
bzImage: Linux kernel x86 boot executable bzImage, ...
core.ko: ELF 64-bit LSB relocatable, x86-64, ...

$ grep -c ' T commit_creds$' /tmp/kallsyms
1
```

利用链的关键三步，不是完整 exp：

```c
ioctl(fd, 0x6677889C, 0x40);        // 设置 off
ioctl(fd, 0x6677889B, buf);         // 从 name+0x40 读 64 字节，前 8 字节是 canary
ioctl(fd, 0x6677889A, 0xffffffffffff0000 | 0x100);
// 有符号比较 len > 63 被负数绕过，强制转换后只拷贝 0x100 字节
```

```text
ROP 概念链：
pop rdi; ret  ->  0
prepare_kernel_cred
mov rdi, rax; ... -> commit_creds
swapgs_restore_regs_and_return_to_usermode + 用户态 iret 帧
```

```text
$ id
uid=0(root) gid=0(root) ...
$ cat /flag
flag{...}
```

**结果**：提权到 root 后读取 flag。原版环境没有 SMEP / SMAP；变种题加上 `+smep,+smap` 后，把 `ret2usr` 换成纯内核 ROP，并在需要时用 `native_write_cr4` 清 CR4 对应位。

::: tip 为什么先讲 modprobe_path
如果模块给的是**任意写**而不是栈溢出，C 组第 1–5 条比 ROP 短得多：改 `modprobe_path` → 放 `/tmp/x` → 执行非法格式文件。它是内核 pwn 入门里成本最低的一条收尾路线；本题的模块给的是栈溢出，所以走 A 组。flag 以原题平台为准。
:::
