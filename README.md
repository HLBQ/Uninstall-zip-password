# Uninstall-zip-password

基于 **7z.dll** + **unrar.dll** 的压缩包密码爆破与解压工具。

支持字符集组合、密码本逐行尝试以及两者的混合模式。

内置 **O(1) 断点恢复机制**，可精确跳转到任意密码位置，无需迭代。

支持通过 -enc 指定密码编码变体（如 utf8），解决 Android / 手机工具按 UTF-8 字节创建的加密包打不开的问题。

---

## 一、编译

### 环境
- Visual Studio 2022（MSVC v143）
- **Release | x64**

### 步骤
1. 打开 `7z_to_dll.sln`
2. 选择 **Release** + **x64**
3. 产物：`x64\Release\7z_to_dll.exe`

### 依赖 DLL

| DLL | 来源 | 说明 |
|-----|------|------|
| `7z.dll` | 安装7-zip程序 , 从安装目录中 `C:\Program Files\7-Zip\7z.dll` 复制并重命名  |
| `unrar.dll` | 下载aawc/unrar源码，编译出dll `unrar-7.13.0\UnRARDll.vcxproj`（Release x64） |

> [获取 unrar.dll   请认准：https://github.com/aawc/unrar](https://github.com/aawc/unrar)

> [获取 7z.dll  请认准：https://7-zip.org/](https://7-zip.org/)

---

## 二、命令行用法

### 打包模式

```
7z_to_dll.exe -z <目录/文件> -o <生成位置> [-n <名称>] [-k <质量>] [-i <类型>] [-d]
```

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `-z <路径>` | — | 打包模式，要压缩的目录或文件 |
| `-o <目录>` | — | 输出目录 |
| `-n <名称>` | 自动 | 输出文件名 |
| `-k <质量>` | 5 | 压缩等级：0=仅存储, 1=极速, 3=快速, 5=标准, 7=最大, 9=极限 |
| `-i <类型>` | zip | 压缩格式：`zip` /`7z` /`bz2` /`xz` /`wim` /`tar` /`gz` |
| `-d` | 否 | 打包后删除源文件 |

```cmd
:: 案例：
7z_to_dll.exe -z myfolder -o ./
7z_to_dll.exe -z myfolder -o ./ -n backup -k 9 -i 7z
7z_to_dll.exe -z myfile.txt -o ./ -n test -d
```

### 解压模式

```
7z_to_dll.exe -e <压缩包> [-o <目录>] [-ps <密码>] [-k <类型>] [-enc <编码>] [-d]
```

| 参数 | 说明 |
|------|------|
| `-e <压缩包>` | 解压模式，压缩包路径 |
| `-o <目录>` | 输出目录 |
| `-ps <密码>` | 解压密码（可选） |
| `-k <类型>` | 强制指定压缩格式 |
| `-enc <编码>` | 密码编码变体，**支持编码**：`utf8` /`gbk`(默认) /`gb2312`/`big5`/`sjis` |
| `-d` | 解压后删除压缩包及其所有分卷 （不稳定）|

```cmd
:: 案例：
7z_to_dll.exe -e 测试.7z -o extracted
7z_to_dll.exe -e archive.rar -o output -ps 1234
7z_to_dll.exe -e temp_test.zip -o ./ -ps 1234 -d
```

### 破解模式

```
7z_to_dll.exe <压缩包> -c <字符集> -ts N -te N [-p <密码本>] [-s N] [-e N] [-k <类型>] [-b|-nb] [-enc <编码>]
7z_to_dll.exe <压缩包> -p <密码本> [-s N] [-e N] [-b|-nb] [-enc <编码>]
```

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `-c <文件>` | — | 字符集文件文档路径（第一行即为字符集） |
| `-ts N` | — | 暴力组合最小长度 |
| `-te N` | — | 暴力组合最大长度 |
| `-p <文件>` | — | 密码本文件文档路径，每行一个密码，**优先于暴力组合执行** |
| `-s N` | 1 | 起始位置（全局序号，含密码本+暴力组合） |
| `-e N` | 末尾 | 结束位置 |
| `-pt N` | 1 | 打印步长；`1`=全打印, `0`=暴力静默, `N`=每N条打印一次（密码本段不受影响） |
| `-k <类型>` | 自动 | 压缩格式：`7z`/`zip`/`rar`/`bz2`/`xz`/`wim`/`tar`/`gz` |
| `-b` | 自动 | 强制缓存压缩包到内存 |
| `-nb` | 自动 | 禁用内存缓存 |
| `-enc <编码>` | — | 密码编码变体，**支持编码**：`utf8` /`gbk`(默认) /`gb2312` /`big5` /`sjis` |

```cmd
:: 案例：

:: 纯暴力模式：字符集 1234，4位长度
7z_to_dll.exe 测试.7z -c charset.txt -ts 4 -te 4

:: 纯密码本模式
7z_to_dll.exe 测试.7z -p passwords.txt

:: 密码本 + 暴力组合（密码本优先）
7z_to_dll.exe 测试.7z -c abc.txt -ts 1 -te 3 -p pb.txt

:: 断点续传：从全局第 50 条开始到第 100 条
7z_to_dll.exe 测试.7z -c abc.txt -ts 2 -te 4 -s 50 -e 100

:: 强制内存缓存
7z_to_dll.exe 测试.7z -c 1234.txt -ts 4 -te 4 -b

:: 指定密码编码变体（解决 MT管理器/手机工具按 UTF-8 创建的中文密码包）
7z_to_dll.exe 特殊压缩包.zip -p 密码.txt -enc utf8
```

### 断点与总数的计算规则

```
示例：密码本 10 条 + 暴力组合 256 条 = 总数 266

全局序号：    1 ~ 10     = 密码本
             11 ~ 266   = 暴力组合

命令：-s 50 → 跳过密码本 10 条 + 暴力前 39 条，从第 40 条暴力组合开始
      -e 100 → 到第 90 条暴力组合结束
```

---

## 三、输出格式

所有输出通过 **stdout**（UTF-8 字节流），每行 `|` 分隔，方便 Python 采集。

### 状态行

```
[START]|总数=266|起始=50|结束=100|缓存=内存
[INFO]|密码本=10条|组合=256条
[STATUS]|50|266|1112          ← 当前第 50 条，密码 1112
[STATUS]|51|266|1113
...
[FOUND]|1234                   ← 密码找到
[DONE]|NOT_FOUND               ← 未找到
[ERROR]|错误描述                ← 异常
```

### 打包进度

```
[INFO]|压缩目录: D:\src → D:\out\src.zip 等级=5
[COMPRESS]|0
[COMPRESS]|50
[COMPRESS]|100
[INFO]|删除原文件: D:\src     ← 使用 -d 时
[DONE]|打包完成 → D:\out\src.zip
```

### 解压进度

```
[INFO]|分卷合并完成, 共27MB
[INFO]|开始解压 → D:\out
[EXTRACT]|0
[EXTRACT]|50
[EXTRACT]|100
[INFO]|删除压缩包: D:\test.zip  ← 使用 -d 时
[DONE]|解压完成
```

### 退出码

| 码 | 含义 |
|----|------|
| 0 | 成功 |
| 1 | 参数不足 |
| 2 | 文件不存在 |
| 3 | 压缩包不存在 |
| 4 | 字典/密码本为空 |
| 5 | 断点超出总数 |
| 6 | 密码未找到 |
| 7 | 运行时错误 |
| 11 | 无法加载 DLL |

---

## 四、内存缓存（测试）

- 缓存决策：文件 `< 1GB` 且可用内存充足时自动启用
- `-b` 强制缓存，`-nb` 禁用缓存
- 已缓存的压缩包通过 `BitMemExtractor::test()` 验证，**零磁盘 I/O**
- 缓存显示：`大小=##`

---

## 五、RAR 双验证机制
#### 在实践测试中，我们发现,7z.dll无法处理rar加密文件名,而unrar.dll无法处理分卷rar,于是我们便采用双校验机制
```
unrar 验证密码成功
  → 用假密码再测一次
    ├─ 假密码失败 → unrar 可靠，密码正确
    └─ 假密码也成功 → unrar 不可靠
       → 回退 bit7z 重新验证
```

---

## 六、Python 集成

```python
import subprocess

def crack(exe, archive, charset, ts, te, pb=None, start=1, end=0):
    """调用并实时输出进度"""
    cmd = [exe, archive, "-c", charset, "-ts", str(ts), "-te", str(te)]
    if pb: cmd += ["-p", pb]
    if start > 1: cmd += ["-s", str(start)]
    if end > 0: cmd += ["-e", str(end)]

    p = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                         text=True, encoding="utf-8", bufsize=1)
    for line in p.stdout:
        line = line.strip()
        if line.startswith("[STATUS]|"):
            parts = line.split("|")
            print(f"\r进度: {parts[1]}/{parts[2]}  当前: {parts[3]}", end="")
        elif line.startswith("[FOUND]|"):
            print(f"\n密码: {line.split('|')[1]}")
            break
        elif line.startswith("[DONE]|"):
            print("\n未找到")
            break
    p.wait()
```

---

## 七、支持格式

| 格式 | 打包 | 破解 | 解压 | 分卷 |
|------|------|------|------|------|
| 7z | ✅ | ✅ | ✅ | ✅`.7z.001` |
| ZIP | ✅ | ✅ | ✅ | ✅`.zip.001` / `.part1` |
| RAR | ❌ | ✅ | ✅ | ✅`.part1.rar` / `.r00` |
| RAR(加密文件名) | ❌ | ✅ | ✅ | ？ |
| BZip2 | ？ | ？ | ？ | — |
| XZ | ？ | ？ | ？ | — |
| WIM | ？ | ？ | ？ | — |
| TAR | ？ | ？ | ？ | — |
| GZip | ？ | ？ | ？ | — |


>有一些格式我也不知道怎么压缩出来的 ,所以用  “**?**”  来表示 ,因为理论上可以 ,但我没测试过
---

## 八、多线程

> ⚠️ 本工具已不再支持多线程。

- 破解全程为单线程执行（密码本阶段与暴力组合阶段均为单线程）
- 已移除 `-tr`（线程数）与 `-bt`（批次大小）参数
- 原因：`unrar.dll` 不可重入，多线程调用存在崩溃风险，且实际收益有限

---

## 九、项目结构

```
./
├── 7z_password_cracker.cpp   ← 主程序
├── 7z_to_dll.vcxproj          ← VS 项目配置
├── x64/Release/
│   └── 7z_to_dll.exe          ← 编译产物(那两个dll记得放在同目录)
└── README.md
```

---

## 十、密码编码变体

**支持编码**：`utf8` /`gbk`(默认) /`gb2312`/`big5`/`sjis`
不写 -enc 时仅按默认尝试，失败不会回退到其他编码，因此密码总数不因编码变体而改变。

>**ps:**之所以增加这个功能，是因为有一些群友给我发的压缩包中使用了中文密码,但是我用电脑居然解不开,用手机就能解开,所以想到可能是编码问题

## ALL、常见问题

| 问题 | 解决 |
|------|------|
| 崩溃 `0xC0000409` | 7z.dll 弄错了，换 64 位（>1500KB） |
| 密码本中有密码但没找到 | 也许密码在断点范围之外，检查 `-s` / `-e` |
| Python 中文乱码 | `subprocess.Popen(encoding='utf-8')` |
| 使用中文密码出错 | `尝试使用-enc 指定密码编码变体为 utf8` |

<img width="744" height="400" alt="屏幕截图 2026-07-27 121633" src="https://github.com/user-attachments/assets/a5331239-d68f-47bd-9370-f9b0d0a32292" />


