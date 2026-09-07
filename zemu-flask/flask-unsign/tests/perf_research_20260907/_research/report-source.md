# zemu-flask 性能研究：实际执行路径、实测与优化顺序

日期：2026-09-07。面向本项目维护者。研究对象是当前工作树的 C++ 实现，重点为 Windows / Ryzen 9 7940HX / RTX 4060 Laptop GPU 上的单 Cookie 字典与掩码搜索。

**结论：优先修复混合调度覆盖性，再优化进程复用与字典表示；CPU 内核优先研究轮展开、固定消息 schedule 和候选打包。GPU 内核调参应排在端到端数据准备之后。** 本次完成 30 余个定向 Web 检索，并读取 Microsoft、Khronos、NVIDIA、Intel、AMD、GCC、Google Benchmark、hashcat 一手资料。源码注释中的速率、历史实验结论、复杂度描述均未直接作为事实采用。

本次没有修改生产源码、默认引擎或原有二进制。新增的是独立实验、原始测量和这份 Markdown 报告。已有未提交修改保留。

**1. 最先决定优化方向的实测**

使用当前源码重新编译的 baseline.exe，编译参数与 build.sh 的 Windows 分支一致：MSYS2 UCRT64 GCC 16.1.0，-O3、C++26、静态链接、zlib。源文件和二进制 SHA-256 见 research_metadata.json。设备名称由本机读取，NVIDIA 驱动为 610.88。测试内容是合成无命中目标，未访问外部目标系统。

完整进程计时从 Python 启动 CLI 前开始，到子进程退出且管道读取完成为止。每场景先预热一次，再以固定随机种子交错执行三轮；文件缓存与内核磁盘缓存预热，每轮仍启动新进程。没有改变电源计划、驱动、GPU 时钟或后台应用。随机交错有助于减少顺序偏差，但不能消除频率和调度噪声。[Google Benchmark：随机交错](https://github.com/google/benchmark/blob/main/docs/random_interleaving.md)、[测量方差来源](https://github.com/google/benchmark/blob/main/docs/reducing_variance.md)。

| 工作量 | 引擎 / 线程 | 端到端中位数 | 最小–最大 |
|---|---|---:|---:|
| 1 亿个 8 位数字掩码 | CPU / 16 | 1.923 s | 1.847–1.955 s |
| 同上 | CPU / 32 | 1.369 s | 1.170–1.506 s |
| 同上 | OpenCL / 16 | 2.337 s | 2.285–2.378 s |
| 同上 | auto / 16 | 2.540 s | 2.493–2.829 s |
| 同上 | auto / 32 | 2.938 s | 2.767–3.048 s |
| 1600 万词、160 MB 文件 | CPU / 16 | 1.468 s | 1.460–1.555 s |
| 同上 | CPU / 32 | 1.423 s | 1.409–1.490 s |
| 同上 | OpenCL / 16 | 3.468 s | 3.462–3.499 s |
| 同上 | auto / 16 | 3.423 s | 3.423–3.514 s |
| 同上 | auto / 32 | 3.402 s | 3.377–3.572 s |

此处 OpenCL 的线程参数主要用于主机字典打包，不是 GPU work-group 大小。auto 结果仅描述当前程序的实际运行时间；下面发现的覆盖性缺陷使其不能用作完整搜索正确性的证明。

换成同一 serve 进程，先执行 gpuinfo 初始化，再连续处理三轮请求：

| 工作量 | CPU / 32 | OpenCL / 16 | auto / 32 |
|---|---:|---:|---:|
| 1 亿掩码，请求完成中位数 | 1.302 s | 0.307 s | 0.228 s |
| 1600 万字典，请求完成中位数 | 1.408 s | 1.429 s | 1.401 s |

serve 掩码纯 GPU 的三次为 0.179 / 0.344 / 0.307 s，波动仍然明显。这组实验按固定顺序运行，没有和 fresh CLI 交错，也未同时开启 nvidia-smi，因此约 2.34→0.31 s 是本次观察到的使用模式差异，不能作为控制所有变量的严格 A/B 倍率。两个新 serve 进程的首个 gpuinfo 分别耗时 2.480 / 2.011 s，支持 GPU 初始化的累计成本值得优先处理，但尚未细分到平台枚举、context、binary build 或内存管理。

本次新编译程序的 SHA-NI 自测通过；现有 test_vectors.py 的 **86 项检查全部通过**。另设的新夹具仍复现 auto 漏查，说明现有回归覆盖存在空白。CUDA 没有做本机性能验证。

**2. 代码实际做了什么，哪些注释不能用来推导性能**

| 主题 | 实际执行逻辑 | 对优化判断的影响 |
|---|---|---|
| 纯 CPU 字典“流式” | [crack_cpu.cpp:124](D:/CTFtool/ZM/zemu-flask/flask-unsign/src/crack_cpu.cpp:124) 用 getline 和 push_back 构建整份 vector<string>；加载返回后，:149 才进入搜索。 | 当前不是边读边算，也没有避免全量驻留。 |
| auto 字典启动顺序 | [flask.cpp:846](D:/CTFtool/ZM/zemu-flask/flask-unsign/src/flask.cpp:846) 完成全量加载，:891 起做两遍打包，:987 才启动 CPU 搜索线程。 | CPU/GPU 搜索都不能覆盖读取与打包的整个前置阶段。 |
| CPU 主验证器 | [flask.cpp:672](D:/CTFtool/ZM/zemu-flask/flask-unsign/src/flask.cpp:672) 选择标量函数；:676–677 另选 AVX512×16 / AVX2×8 批量验证。 | 大部分候选不是逐个走 SHA-NI；只优化 verifyFast 会错过主要热路径。 |
| CPU 字典取词 | [crack_cpu.cpp:179](D:/CTFtool/ZM/zemu-flask/flask-unsign/src/crack_cpu.cpp:179) 直接引用 words 的 data/size。 | 已经避免批次中复制整个字典字符串。 |
| CPU 掩码生成 | [crack_cpu.cpp:419](D:/CTFtool/ZM/zemu-flask/flask-unsign/src/crack_cpu.cpp:419) 每块做一次序号除法展开，块内用里程表增量生成。 | “每个候选都有多次除法”不成立；但每个 SIMD 槽仍复制 cand。 |
| OpenCL 上传 | [ocl.cpp:533](D:/CTFtool/ZM/zemu-flask/flask-unsign/src/gpu/ocl.cpp:533) 在 q2 预取，q 中 kernel 等待 copy event，并预取下一块。 | pinned 与双队列预取已经存在；不能建议从零添加它们。 |
| CUDA 上传 | [nvrtc.cpp:335](D:/CTFtool/ZM/zemu-flask/flask-unsign/src/gpu/nvrtc.cpp:335) cuMemcpyHtoD 同步上传，字典整份上传；:488–493 默认 stream 发 kernel，context 同步后读结果。 | CUDA 的异步分块流水确实尚未实现。 |
| GPU 编译缓存 | [ocl.cpp:285](D:/CTFtool/ZM/zemu-flask/flask-unsign/src/gpu/ocl.cpp:285) 已读写二进制缓存；CUDA 也有自有缓存。 | 磁盘缓存不等于复用进程内 context；“新增 JIT 缓存”不是主要缺口。 |
| GPU 掩码运算 | [kernel_cl.h:378](D:/CTFtool/ZM/zemu-flask/flask-unsign/src/gpu/kernel_cl.h:378) 已做魔数除法，:395 起已有长度 1…24 的打包分支。 | 不能把这些已存在优化再算一遍。 |

注释声称某个展开、内循环或寄存器实验更慢，最多是历史线索：没有对应编译器、源版本、完整数据与计时范围，就不能认定该方向永远无效。反过来，一般性优化原则也不能推翻本机实测。

**3. 性能优化的前置条件：当前混合路径会漏查**

**已实测：GPU 不支持的长词在 auto 中丢失。** 新夹具第一行是 40 个 L，后面是 200 万普通短词；Cookie 的密钥就是第一行。serve 预热 GPU 后，ZK_GPUTHRESH=1、--threads 1：

| 模式 | 实际结果 |
|---|---|
| cpu | 输出 40 字节目标，rc=0 |
| gpu | GPU 搜完后 CPU 补验，输出目标，rc=0 |
| auto，第 1/2/3 次 | 都报告未命中，rc=1 |

原始记录在 hybrid_correctness.json，生成与执行逻辑在 followup_probe.py。

原因由控制流直接闭合：[flask.cpp:899](D:/CTFtool/ZM/zemu-flask/flask-unsign/src/flask.cpp:899) 和 :956 把长于 stride 或含 NUL 的词从 GPU packed 集合过滤；[ocl.cpp:496](D:/CTFtool/ZM/zemu-flask/flask-unsign/src/gpu/ocl.cpp:496) 先认领原始索引范围，再用 lower_bound 映射到 packed 集合；[crack_cpu.cpp:338](D:/CTFtool/ZM/zemu-flask/flask-unsign/src/crack_cpu.cpp:338) 的 CPU 侧按 head 放弃这些原始范围；auto 的未命中分支直接返回。skippedIdx 补验只在纯 GPU 分支 [flask.cpp:1054](D:/CTFtool/ZM/zemu-flask/flask-unsign/src/flask.cpp:1054)。含 NUL 的词按相同逻辑存在风险，本次未另做 NUL 搜索复现。

**另一个高置信度静态问题：head/tail 双游标认领不是原子区间所有权。** CPU 先 CAS 降低 tail，再读取 head 决定是否丢弃已领区间；GPU 先 fetch_add 扩大 head，再检查 tail，并裁剪真正执行的范围。字典的一种合法交错：

1. 初始 head=H、tail=HI，且 H<LO<HI≤H+16M。
2. CPU 将 tail 从 HI 改为 LO，认领 [LO,HI)，暂未读取 head。
3. GPU 读取 tail=LO，把 head 推到 H+16M，真正执行范围仅 [H,LO)。
4. CPU 恢复，看到 head≥HI，直接丢弃 [LO,HI)。

这段区间两侧都没计算。改为 seq_cst 不能修复此算法交错。掩码还有另一种情况：CPU 先领取最后不足 64K 的区间；GPU fetch_add 先推进 head，随后因旧起点≥新 tail 拒绝任务；CPU 却看到推进后的 head 而丢弃尾区间。这是静态交错证明，尚未用可控调度 hook 做确定性运行复现，不与前述三次实测混为一谈。

建议先建立简单可证明的区间分配器：领取时冻结范围归属，失败领取不得发布虚假的已覆盖 head；每个候选必须归某一侧或明确的待补验集合。每块一次 mutex 也可以作为正确基线，不必先追求 lock-free。GPU eligible 和 skipped 集合分别定义所有权，保留原始词索引。所有边界、故障与取消用例通过后，才比较混合吞吐。

GPU kernel 的共享 found 当前还是普通并发读写；重复词等多命中场景也应采用后端支持的原子发布方案。返回候选最终再由 CPU 验证；“任意合法命中”与“字典最早命中”的语义需分别定义。

**4. 第一优先级：字典数据表示与加载**

独立 loader_probe.cpp 复制了现有 CPU loader 的核心 getline、尾部 CR/LF 去除、空行过滤、push_back 行为。比较三个方案，每个方案一次预热、随后五轮交错测量。读取 1600 万词、160,000,000 字节文件，加载计时不包含后置校验；三个方案的全部词内容及顺序校验和一致，并通过含 CRLF、重复 CR、NUL、中文和无末尾换行的小夹具。

| 独立加载方案 | 加载中位数 | 最小–最大 | 销毁中位数 | 进程峰值工作集 |
|---|---:|---:|---:|---:|
| 当前 getline + vector<string> | 0.989 s | 0.968–1.027 s | 0.050 s | 518.2 MiB |
| 同上，预留容量 | 0.722 s | 0.709–0.768 s | 0.049 s | 493.5 MiB |
| 一次读取 + 连续字节 + 32 位 offset/length | 0.242 s | 0.236–0.259 s | 0.013 s | 279.8 MiB |

预留容量方案的加载时间减少约 27%；连续表示减少约 75.5%，约 4.09 倍加载速率。**这些都是独立 loader 结果，不是完整搜索引擎的 A/B。** offset/length 原型限制文件≤4 GiB，reserve 的 file_bytes/10 估计恰好适配当前夹具；这两个条件都不能原样当生产方案的通用保证。

本机 sizeof(std::string)=32，libstdc++ 小字符串容量为 15。当前 8 字节短词大多在字符串对象内部存放，不能声称每个短词都有一次独立堆分配。真实成本包括 1600 万次容器元素构造、约 512 MB 的对象内容、扩容搬迁、逐行处理和释放。对 >15 字节词，额外字符存储分配才成为新的成本。该实现细节与本机头文件、[GCC basic_string 源码](https://github.com/gcc-mirror/gcc/blob/master/libstdc%2B%2B-v3/include/bits/basic_string.h)一致。

推荐分两步实施：

- 小改动：根据受限采样估计词数、合理 reserve；把 CPU 和非 CPU 两处重复 loader 合并。避免每次插入 reserve，避免按文件大小无界放大内存。
- 主方案：拥有字节缓冲区的 Dictionary 对象，提供 data/size 的词视图和稳定原始序号。大文件用 64 位全局偏移，或分块的 32 位块内偏移。CPU 批验证直接引用视图；GPU packing 也引用同一份数据，避免再生成全量 string 对象。

批量读取和内存映射都值得比较，但当前实验只测了前者。Windows 的文件缓存意味着热文件读取不等于物理磁盘速度；无法把现有 1 秒全归因于磁盘慢。[Microsoft File Caching](https://learn.microsoft.com/en-us/windows/win32/fileio/file-caching)。mmap 还要求正确处理文件视图的 I/O 异常，未证明它一定快于批量读取；不要直接打开 NO_BUFFERING，因为它绕过系统缓存并带来对齐要求。[文件视图访问](https://learn.microsoft.com/en-us/windows/win32/memory/reading-and-writing-from-a-file-view)、[File Buffering](https://learn.microsoft.com/en-us/windows/win32/fileio/file-buffering)。

当目标是很大的字典或尽早找到高概率前缀时，再比较有界分块流水：读取/解析第 k+1 块，同时打包/上传第 k 块并计算前一块。它能降低全量驻留和首候选等待，但生产者队列、块边界、词序与 buffer 生命周期会增加复杂度，不能提前承诺全扫描一定快于连续整批方案。

**5. 第一优先级：进程复用与真实端到端选择引擎**

实际 gpuThreshold 和 gpuDictThreshold 都在进程未热时取 800 万，已热时取 150 万，[flask.cpp:634](D:/CTFtool/ZM/zemu-flask/flask-unsign/src/flask.cpp:634)。除此之外没有按设备、消息长度、字典字节数、打包成本或线程数计算收益模型。Windows 的 auto 大任务走 OpenCL+CPU，并非在 CPU、GPU、CUDA 三者之间动态择优。

本次 1 亿候选已经远大于 800 万，但 fresh CLI 纯 CPU 仍明显更快；serve 纯 GPU 又明显更快。用一条固定候选数阈值不能覆盖这两种使用方式。

最先可用的改进是让连续操作复用现有 serve。需要区分：

- serve 已复用 OpenCL 单例 context、program 和 kernel。
- 每次字典请求仍重新读入、构建 words、分配/打包主机内存、创建设备字典 buffer。
- CPU ThreadGroup 每次请求仍创建新线程；它不是持久 worker pool。

因此，下一步可增加有内存预算与失效检测的已加载字典缓存，复用容量合适的 staging/device buffer。缓存内容至少关联文件标识、大小、修改状态与解析规则；不能为了缓存而读到过期字典。多请求处理仍应遵守当前单例状态的串行约束。

引擎选择应估计完整成本，例如：

Tcpu = Tload + Tcpu_setup + N / Rcpu + Tcleanup

Tgpu = Tload + Tgpu_init + Tpack + Ttransfer_compute + Tcleanup

Tauto 还要考虑开始重叠的时刻、CPU线程数、打包前置等待和正确区间所有权，不能直接写成 N/(Rcpu+Rgpu)。对纯 GPU、没有 packing 差异的简化场景，盈亏点才近似为 Tinit/(1/Rcpu−1/Rgpu)。这里需要实测参数，本报告不据三轮数据给出新的硬编码阈值。

本次 CPU 字典中位样本总耗时 1.423 s、内部搜索约 0.475 s；假设仅搜索阶段快一倍、其余不变，总耗时也只是约 1.185 s，即约 1.20 倍整体提速。纯 GPU 字典的中位样本总耗时 3.468 s，内部搜索约 0.060 s；即便这整个内部搜索阶段免费，fresh CLI 总耗时也只减少约 1.7%。这是以当前阶段定义做的上限估算，解释了为什么现阶段应先优化初始化和加载。

**6. CPU 哈希的真实优化空间**

从 [flask.cpp:230](D:/CTFtool/ZM/zemu-flask/flask-unsign/src/flask.cpp:230)、:461–510、:555–601 的压缩调用，以及 [sha1.h:502](D:/CTFtool/ZM/zemu-flask/flask-unsign/src/sha1.h:502) 的实际尾块构造，可得每个候选：

C = 6 + ceil((salt_bytes+9)/64) + ceil((value_bytes+9)/64)

如果 key_bytes>64，再加 ceil((key_bytes+9)/64)，用于长 HMAC key 折叠。默认 14 字节盐、value≤55、key≤64 时为 8 次 SHA-1 compression；value 为 56–119 时为 9 次。压缩前导点也是 value 的一部分。比较性能必须对齐 value 字节长度，不能拿裸 SHA-1 的 H/s 当 Flask Cookie 的候选/s。

**优先实验 A：固定消息 schedule 预展开。** 当前 HmacFixedMsg 缓存 padding 和 16-word 尾块，但 AVX2/AVX512 的 sha1_block_x* 每批仍重复扩展固定盐和固定 value 的 W[16..79]。SHA-1 的 W 扩展只由消息块决定，因此可在任务初始化时预计算 W[80]，必要时把普通轮的 W[t]+K[t] 合并。当前 chaining state 仍随候选变化，不能缓存一个“盐哈希状态”替代它。该可行性直接来自 [Intel SHA 扩展说明中的 schedule 定义](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sha-extensions.html)。

每个固定块可省去运行时 64 个 schedule 扩展步骤，但 **SHA 压缩次数和 80 轮状态运算没有减少**。分别测 320 B 标量 schedule 加广播，与预广播 AVX512 schedule（每块约 5 KiB）；后者节省广播，也可能增加 L1 压力。长 value 工作负载应单列。这是算法可行、性能未实测的建议。

**优先实验 B：让轮号与寄存器位置静态化。** [flask.cpp:312](D:/CTFtool/ZM/zemu-flask/flask-unsign/src/flask.cpp:312) 与 :403 起仍存在后 60 轮的循环、t&15、t%5 与分支。对本次 baseline.exe 的静态反汇编也能看到 x16 的动态消息下标、栈数组访问和跳转，不只是从 C++ 外观猜测。可比较按 20 轮分段模板展开与完整 80 轮展开，观察汇编体积、栈访问和 cycles/candidate。

当前二进制已有 vprold 和编译器生成的 vpternlogd；“加入旋转指令/三元逻辑指令”不是新优化。展开可能增加代码体积和寄存器压力，GCC 官方也明确循环展开未必加速。[GCC Optimize Options](https://gcc.gnu.org/onlinedocs/gcc/Optimize-Options.html)。不应只加一个 pragma 就宣布解决。

**优先实验 C：减少候选表示的反复转换。** [flask.cpp:529](D:/CTFtool/ZM/zemu-flask/flask-unsign/src/flask.cpp:529) 当前经历 kb[16][64]→iw/ow→tmp 转置→IW/OW。可直接构造一份 SoA key words，从同一 key 表示推导 ipad/opad；推迟 opad 构造以缩短同时活跃的向量生命周期。掩码入口还可以直接更新受进位影响的 word，在命中时才重建字符串。变长字典、长 key 和尾数仍保留通用正确路径。

hashcat 的实际 Flask m29100 掩码内核通过 w[0] 的变动构造候选，并执行两级 HMAC，可借鉴其紧凑表示；它固定 cookie-session 盐，不能照搬成任意 salt 的实现，更不能用其裸 benchmark 替代本项目端到端结果。[hashcat m29100 实现](https://raw.githubusercontent.com/hashcat/hashcat/master/OpenCL/m29100_a3-pure.cl)。

**实现分派与编译选项放在上述实验之后验证。** 当前仅按 ISA 可用性选择 SIMD 宽度；可给实验版增加 SHA-NI、SHA-NI×2、AVX2×8、AVX512×16 override。Intel 的实际 multi-buffer 库存在多种 SHA/HMAC 路径，支持做比较，不证明某一种会在本机获胜。[Intel Multi-Buffer Crypto](https://github.com/intel/intel-ipsec-mb)。AMD 对 Zen 4 的技术文档描述 AVX512 使用 256 位数据通路分两部分执行，因此向量宽度翻倍不能直接推导整体吞吐翻倍；该文档是 EPYC 平台，不能据此外推本笔记本频率行为。[AMD Zen 4 AVX512 说明](https://www.amd.com/content/dam/amd/en/documents/epyc-technical-docs/tuning-guides/58305_amd-epyc-8004-tg-ubuntu.pdf)。

编译已是 -O3，可另测 -flto、-mtune=znver4 和有代表性负载训练的 PGO。mtune 和 march 不是一回事，后者可改变最低指令集要求；通用发行版仍要保留运行时分派。[GCC x86 Options](https://gcc.gnu.org/onlinedocs/gcc/x86-Options.html)。不把 -Ofast、更多线程或更宽 SIMD 当保证提速的开关。

**7. GPU：先修提交与测量，再改数据通路，最后改内核**

**OpenCL 的跨队列提交有规范缺口。** [ocl.cpp:538](D:/CTFtool/ZM/zemu-flask/flask-unsign/src/gpu/ocl.cpp:538) 在 q2 入队 copy；:567 的 q kernel 等 copy event；:580 只 clFinish(q)。程序没有加载或调用 clFlush，q2 的 finish 出现在最终结束或更早的 unmap 阶段，不保证新 copy 已提交。Khronos 要求跨队列事件的生产队列执行显式 flush 或相应隐式 flush。[Khronos clFlush](https://registry.khronos.org/OpenCL/specs/unified/refpages/man/html/clFlush.html)。应提交 copy 后 flush(q2)，检查返回值；这是可移植进度保证修正，不是已证明的提速倍数。

当前两队列 properties=0，未启用 profiling，也没有读取 kernel/copy event 的时间戳。因此日志“kernel+流水上传”只能表示 host 计时段，不能证明传输和计算实际重叠。需要 profiling queue 与 queued/submit/start/end，记录相邻 copy/kernel 区间，并检查初始等待、块间空隙和末尾排空。[Khronos Event Profiling](https://registry.khronos.org/OpenCL/specs/unified/refpages/man/html/clGetEventProfilingInfo.html)。

**已有 pinned 不代表数据通路完成优化。** 当前 OpenCL 在完整 packed 字典上分配 pinned host buffer 和全量 device buffer；下一块拷贝的预取并不覆盖前面的整份读取和两遍 packing。推荐有界 staging ring，把生产与消费串起来，并由完成事件保护槽复用。CUDA 还需要真正的异步 Driver API copy、非默认 streams 与 events；只有 page-locked 分配不会自动产生传输/计算并行。锁页本身有成本，应复用有限容量缓冲，并用 wall time 验证。[NVIDIA CUDA Best Practices：数据传输](https://docs.nvidia.com/cuda/cuda-c-best-practices-guide/index.html#asynchronous-and-overlapping-transfers-with-computation)。

**packing 可以有更便宜的常见路径。** 当前 pass1 和 pass2 都检查长度和 find(NUL)，idxMap.assign 先初始化整份映射，再由 pass2 填写。加载或分块解析时即可顺便记录长度、是否含 NUL、GPU eligibility；全部可处理时映射本来就是 identity，可用标记省去完整 idxMap。只要出现过滤词，就使用稳定的紧凑映射及独立 skipped 所有权。

此外，STRIDE 由全词 maxLen 向上对齐再封顶 32。一个 >32B 的词即使随后被 GPU 排除，也可能让全部短词从 stride=8 膨胀到 32。新长词夹具的 200 万短词确实被打包为约 64 MB，而全是这些短词只需约 16 MB。这直接来自 [flask.cpp:846](D:/CTFtool/ZM/zemu-flask/flask-unsign/src/flask.cpp:846)、:880 的 maxLen→STRIDE 逻辑。应按 GPU eligible 词的最大长度或长度分桶决定 stride，保留长度恰好等于 stride 的正确性；收益需同时算上分桶与映射开销。

**减少同步与内核布局：有条件推进。** OpenCL 和 CUDA 块大小固定 2^24；每块 finish/context synchronize 后还做阻塞结果读取。可比较减少一次冗余全队列等待，但必须保留完成语义、异常传播、取消和命中检查。更大块会延长停止延迟，先查 gap 是否真的占比高，再按目标 kernel 时长自适应块大小。

GPU 字典目前是 words+idx*stride 的 AoS 字节读取，逐个扫描到 NUL，再打包 HMAC 的 ipad/opad。可比较 lengths 数组、一次大端 word 打包，以及按 warp tile 排列的 SoA；同时把 CPU 转换和 PCIe 字节数计入总耗时。本次字典 GPU 核心阶段很短，这项优先级低于加载与初始化。

**调参不能只看一个 work-group 数。** OpenCL tuneLws 只用合成掩码测试一个消息形状，所得一个 lws 同时用于字典；CUDA 的 ZK_CB 只影响掩码，字典仍固定 256。应按 mask/dict、valueBlocks、npos/stride 和真实长度分布分别测，调参预算按长短任务摊销。hashcat 的 autotune 实际还调 loops、threads、accel，不能把“尝试几个 LWS”视为完整自适应。[hashcat autotune 源码](https://raw.githubusercontent.com/hashcat/hashcat/master/src/autotune.c)。

ocl 日志的 PRIVATE_MEM_SIZE 不等同于精确 spill，WORK_GROUP_SIZE 也不是实际 occupancy。Khronos 对前者定义的是每 work-item 最低私有内存需求。[Khronos Kernel Work-group Info](https://registry.khronos.org/OpenCL/specs/unified/refpages/man/html/clGetKernelWorkGroupInfo.html)。更激进的多候选内循环、长度/固定消息 JIT 特化，应结合 SASS 和 local memory 计数器判断；动态索引数组及寄存器不足都可能产生 local memory 访问。[NVIDIA Nsight Compute Profiling Guide](https://docs.nvidia.com/nsight-compute/ProfilingGuide/index.html#memory-workload-analysis)。

缓存另需完善 key：OpenCL 当前主要依赖人工 magic 和 deviceName；应关联 source hash、编译选项、设备与 driver 标识，编译缓存与调参结果分开。内核改动后如果仍读到旧缓存，所谓 A/B 不成立。增加 JIT 特化之前先修这一点。没有证据支持此时优先引入 CUDA Graphs，或认定换 CUDA 本身必然快于 OpenCL。

**8. 如何测，才能判断下一次改动真的有效**

建议提供低开销、可关闭的结构化阶段记录，明确阶段是否重叠：

| 层次 | 应记录内容 | 本次状态 |
|---|---|---|
| 外部用户耗时 | CLI 启动→退出；serve 请求写入→完成标记；首次候选/命中响应 | 已测完成耗时；未独立测首候选 |
| 字典准备 | 读字节、解析、容器构造、分配/锁页、计数、映射、打包、释放 | 已做 loader 独立对照；生产阶段尚未拆全 |
| CPU | 线程创建/等待、生成/打包、验证、有效候选数 | 仅有生产搜索段和静态反汇编 |
| GPU | 初始化/API阶段；copy/kernel 事件时间与提交间隙 | 当前仅 host 段；未采事件或 Nsight |
| 正确性 | 每个原始候选归属、实际验证数、跳过与补验、返回密钥再验签 | 新夹具已发现覆盖缺陷 |

[flask.cpp:876](D:/CTFtool/ZM/zemu-flask/flask-unsign/src/flask.cpp:876) 的“dict 打包”计时包含 oclHostAlloc→ocl() 的初始化；它不是纯 packing。CPU 的 runPool 时间没有包含调用它之前的 loadWords。GPU 的 attempts 在混合中累加 raw 范围，而非必然实际执行的 eligible 哈希数；CPU SIMD 命中时也按 hit+1 记数，尽管批函数已经处理完整批次。不要用有命中任务的这个计数做内核吞吐基准。

本次 nvidia-smi 记录 482 个样本，包含 P0/P3/P5/P8，SM 时钟覆盖 210–2655 MHz。但样本同时覆盖 CPU 阶段与等待阶段，不能据此认定哪次 kernel 降频。NVIDIA 对 utilization 定义的是采样窗内有 kernel 执行的时间比例，采样窗因设备而异；它不是本程序的 occupancy 或指令效率。[nvidia-smi 文档](https://docs.nvidia.com/deploy/nvidia-smi/index.html)。下一轮应将设备事件与主机时间关联；必要时用 WPR/WPA 分析线程等待、CPU 栈、文件 I/O 和分配。[Microsoft WPR/WPA](https://learn.microsoft.com/en-us/troubleshoot/windows-server/support-tools/support-tools-xperf-wpa-wpr)。

验收矩阵至少覆盖：

- key 长度 1、8、15、16、24、32、33、64、65、长 key，以及含 NUL 和中文。
- value 长度跨 55/56、119/120，压缩 Cookie、自定义 salt、GPU 上限与 CPU 回退。
- 字典首行、中部、末尾命中与全扫描未命中；skipped 位于 GPU 头部、CPU 尾部和交界。
- CPU 批宽边界与 1024/4096/65536/2^24 分块边界；线程创建失败、GPU 中途失败、取消。
- 冷文件与热文件、新进程与热 serve；短词、混合长度和大于内存预算的文件。
- 同时验证完整 Cookie 结果和 candidate 覆盖；更快但漏查的版本直接淘汰。

下一轮 A/B 固定源版本/编译参数，变更一项；正确性通过后，交错运行至少 5–9 轮并报告每轮数据、中位数和离散范围。先做 profile 定位，最终计时关闭高开销 profile，防止测量本身改变程序行为。CPU affinity、固定频率等若需用于控制实验，应另列环境，不能混入用户默认运行结果。

**9. 推荐的实施顺序与停止条件**

| 顺序 | 改动 | 为什么先做 | 通过条件 |
|---|---|---|---|
| P0 | 修 skipped 覆盖、区间认领、OpenCL 跨队列 flush | 当前有确定漏查与规范缺口 | 新夹具、边界交错与原回归通过 |
| P1 | 统一 loader，合理 reserve；再接入连续缓冲+词视图 | 已有独立约 27% / 75.5% 加载耗时下降证据 | 完整 CPU/GPU 字典端到端与峰值内存改善，字节语义不变 |
| P1 | 连续任务复用 serve，缓存/复用字典与有限容量 buffer | 当前新进程 GPU 初始化约 2 s；serve 字典仍反复准备 | 分开首请求/后续请求；缓存失效正确；有内存预算 |
| P1 | 完善分阶段计时与引擎成本模型 | 现有 8M/1.5M 阈值无法反映真实成本 | 不以 kernel H/s 代替 wall time；修正确性后重新校准 |
| P2 | SIMD 固定 schedule、轮展开、直接 key-word 批次 | 真实指令和表示存在重复工作 | cycles/candidate 与端到端同时报告，保持通用回退 |
| P2 | eligibility stride、identity map、分块读取/打包/GPU管线 | 消除不必要的全量数据搬动，改善早停与内存 | 确认 event overlap；所有原始词可追溯 |
| P2/P3 | 按负载调 LWS/chunk/线程，CUDA async、SoA、JIT 特化、LTO/PGO | 收益取决于负载和机器码 | 分别 A/B；缓存版本明确；吞吐不能牺牲正确性和停止延迟 |

如果只先选两项性能工作，选 **连续字典表示** 和 **复用现有 serve/字典资源**。如果主要负载是长期掩码计算，则在修复调度覆盖后，提高 **CPU schedule/轮展开实验** 与 **GPU 真实负载调参** 的优先级。

**10. 复现材料与研究边界**

所有相对文件名均位于本报告所在目录 tests/perf_research_20260907：

- research_bench.py：fresh CLI 预热、交错三轮、GPU 状态采样；benchmark_results.json 保存原始 stderr 和计时。
- loader_probe.cpp：三个加载方案；loader_results.json 保存 18 次记录（每种一次预热+五次计量）。
- followup_probe.py：加载语义对照、serve 请求测试、auto 长词漏查夹具；serve_results.json 与 hybrid_correctness.json 保存输出。
- research_metadata.json：源码/二进制 hash、系统和汇总；gpu_telemetry.csv 保存设备样本。
- regression.log：对新编译 baseline.exe 执行现有测试，86 PASS、0 FAIL；run_regression.py 只重定向测试的 TOOL 路径。
- build_probes.ps1：从当前工作树重建独立二进制的命令。

测试脚本读取项目已有 tests/wl-bench16.txt；本次确认为 1600 万词、160 MB。loader 原型以计时后完整内容/顺序校验和作对照，它不是生产级字典格式实现。没有接入 flat loader、修改 SHA 内核、改变默认阈值或修复上述缺陷；本次产出是研究结论与可复现证据。

未完成的性能实验包括 CUDA、本机 event/Nsight 计数器、冷盘、真实命中位置分布、非本机 CPU/GPU 和所有候选优化的端到端 A/B。因此“已实现”“已测改善”“算法可行但收益未知”“静态正确性推导”在报告中分别标注。30 余次检索后停止继续泛搜，是因为主要证据缺口已经变成这些本机实验，而不是缺少更多一般性网页。当前在线文档和开源 main/master 可能更新；实际实施应固定版本或 commit。

