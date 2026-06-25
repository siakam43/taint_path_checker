# taint-path-checker Skill 设计文档

## 概述

开发一个纯 markdown 文档组成的 Claude Code skill，名为 `taint-path-checker`。核心功能：分析 C 语言函数调用链中的全部函数代码，追踪外部输入（污点数据）的传递过程，挖掘因未校验导致的安全漏洞。

### 业务领域

低层嵌入式/系统级 C 代码，包括：
- Linux 内核驱动
- 移动设备启动链组件（UEFI、BL31、BL2、XLoader）
- 移动协处理器固件（ISP、SensorHub、GPU）

### 设计目标

- 精准：宁可漏报，不要误报
- 可追溯：每个漏洞有完整的污点传播路径分析
- 可去重：基于代码位置生成确定性漏洞 ID
- 可靠输出：每次执行必须生成输出文件

---

## 文件结构

```
taint_path_checker/
├── SKILL.md                                          # skill 本体
└── .claude/skills/taint-path-checker/SKILL.md -> ../../../SKILL.md  # 软链（测试用）
```

## 触发方式

- 命令触发：`/taint-path-checker project_dir xxx.json`
- 参数 `project_dir`：待分析项目路径，可选，默认当前目录（不向用户确认）
- 参数 `xxx.json`：调用链 JSON 文件，文件名中的 `xxx` 即 callchainID（例如 `593393969.json` 对应的 callchainID 为 `593393969`）
- 仅命令触发，不通过自然语言关键词触发

---

## Skill 内部结构

采用混合式组织：步骤框架 + 硬性检查门 + 每步内的灵活分析空间。

```
SKILL.md（单文件）
├── 一、角色与任务概述
├── 二、输入解析（步骤0）
├── 三、获取目标代码（步骤1）
├── 四、污点数据追踪（步骤2）
├── 五、危险使用点与校验检查（步骤3+4）
├── 六、报告输出（步骤5）
└── 七、排除清单与原则
```

---

## 详细设计

### 一、角色与任务概述

LLM 角色定位为：嵌入式 C 代码安全分析专家。明确分析范围 vs 漏洞挖掘范围的区别：
- **分析范围**：整个 project_dir，查找函数定义、变量定义时可在全项目浏览
- **漏洞挖掘范围**：仅限调用链中的函数，链外函数跟进追踪但漏洞判定回归链内

### 二、输入解析（步骤0）

**输入格式**（调用链 JSON）：
```json
{
    "callchainID": "593393969",
    "chain": [
        {"func": "npu_ioctl_send_request", "file": "/srv/code/a.c", "begin_line": "213"},
        {"func": "npu_sem_alloc", "file": "/srv/code/a.c", "begin_line": "367"}
    ]
}
```

- 调用链始终为线性，chain 数组顺序即调用顺序，第一个函数为入口函数
- 入口函数所有参数默认视为污点（外部可控），追踪过程中可排除明显非外部输入的参数（如内核内部指针）
- 输出目录：`{project_dir}/.ethunter_out/taint-path-checker/`，不存在则创建

### 三、获取目标代码（步骤1）

- 遍历 chain 数组，按 `file:begin_line` 定位每个函数
- 在 project_dir 中搜索函数定义
- 源码不存在的函数跳过并记录至报告

### 四、污点数据追踪（步骤2）

#### 4.1 直接传播

| 模式 | 示例 | 说明 |
|------|------|------|
| 简单赋值 | `b = a;` | 直接传播 |
| 复合赋值 | `b += a;` | 运算结果仍含污点 |
| 类型转换 | `b = (uint32_t)a;` | 强转不消除污点 |
| 条件表达式 | `b = cond ? a : c;` | 任一分支含污点则结果污点 |
| 函数返回值 | `return a;` | 将污点传播到调用方 |

#### 4.2 指针与内存

| 模式 | 示例 | 说明 |
|------|------|------|
| 指针传递 | `foo(&a)` → `*ptr = ...` | 实参地址绑定形参指针，形参内写入污染实参 |
| 指针赋值 | `ptr = &a; *ptr2 = *ptr;` | 指针间解引用传播 |
| 数组索引 | `arr[idx]` 若 idx 为污点 | 索引本身污染，此处仅追踪传播 |
| memcpy/memmove | `memcpy(dst, src, n)` | 若 src 污点→dst 污点；若 n 污点→不完整复制 |
| strcpy/strncpy | `strcpy(dst, src)` | src 污点→dst 污点 |
| memset | `memset(ptr, val, n)` | 仅 n 为污点时关注（不完整初始化） |

#### 4.3 结构体与联合体

| 模式 | 示例 | 说明 |
|------|------|------|
| 结构体整体赋值 | `s2 = s1;` | s1 污点→s2 整体污点 |
| 成员赋值 | `s.member = a;` | 仅 s.member 被污染 |
| 成员读取 | `b = s.member;` | member 污点→b 污点 |
| 嵌套结构体 | `s.outer.inner = a;` | 递归追踪到最内层成员 |
| 联合体 | `u.i = a; ... u.f` | 同一内存的不同解释，任一成员写入污点则全联合体污点 |
| 指针成员 | `s->ptr = &a;` | s->ptr 指向污点，但 s 自身不污 |

#### 4.4 嵌入式特有模式

| 模式 | 示例场景 | 说明 |
|------|----------|------|
| MMIO 读写 | `readl(mmio_addr + offset)` | offset 污点则读结果污点 |
| DMA 缓冲区 | `dma_buf[idx]` | 来自硬件/DMA 的数据视为外部输入 |
| 共享内存 | `shm->field` | 跨组件共享内存数据 |
| ioctl/sysfs 参数 | `copy_from_user(kbuf, ubuf, len)` | ubuf 和 len 均为污点，复制后 kbuf 污点 |
| 固件间 IPC | `ipc_msg->payload` | 协处理器间消息数据 |
| 配置表/ACPI/DT | `acpi_table->entry` | 固件/硬件提供的配置数据 |

#### 4.5 自定义函数识别

**重要**：代码中存在大量自定义封装函数，功能类似标准库函数。必须根据函数语义（命名、参数模式、上下文）识别，而非仅靠函数名匹配。例如：
- `hw_mem_copy(dst, src, n)` → 语义等同于 memcpy
- `safe_read(reg)` → 语义等同于 MMIO 读取
- `ipc_get_msg(buf, &len)` → 语义等同于 IPC 消息接收

#### 4.6 追踪规则

- 同名变量区分：分析代码上下文，结合数据流区分不同作用域的同名变量
- 结构体成员区分：结构体变量为污点则全部成员为污点；污点数据赋值给结构体成员则仅该成员为污点
- 链外函数追踪：污点经过调用链外的函数时需跟进追踪该函数对污点的操作，但最终漏洞判定回归链内函数

### 五、危险使用点与校验检查（步骤3+4）

#### 5.1 危险使用模式清单

##### 内存越界

| 模式 | 示例 | 安全影响 |
|------|------|----------|
| 污点作数组索引 | `buf[idx]` idx 为污点 | OOB read/write |
| 污点控制内存操作长度 | `memcpy(dst, src, len)` len 污点 | 堆/栈溢出 |
| 污点控制拷贝长度 | `strncpy(dst, src, n)` n 污点 | 字符串越界 |
| 污点作指针偏移 | `ptr + offset` offset 污点 | 任意地址访问 |
| 污点控制循环边界 | `for(i=0; i<tainted; i++)` | 循环内越界访问 |

##### 指针危险使用

| 模式 | 示例 | 安全影响 |
|------|------|----------|
| 污点指针解引用 | `*tainted_ptr` | 任意地址读写 |
| 污点作函数指针 | `tainted_func()` | 任意代码执行 |
| 空指针检查缺失 | `ptr = get_from_taint()` 后未判空 | Null pointer dereference |

##### 整数安全

| 模式 | 示例 | 安全影响 |
|------|------|----------|
| 污点参与长度计算 | `size = tainted * elem_size` | 整数溢出→小缓冲区 |
| 污点参与加减 | `end = start + tainted` | 回绕/溢出→越界 |
| 有符号/无符号混淆 | `(int)tainted < MAX` 但 tainted 为 unsigned | 类型混淆绕过校验 |

##### 释放后使用 / 双重释放

| 模式 | 示例 | 安全影响 |
|------|------|----------|
| 污点控制释放对象 | `kfree(ptr_array[tainted])` | 非预期对象释放→UAF/DF |
| 污点影响引用计数 | `refcount_dec(&obj[tainted]->ref)` | 错误释放→UAF |

##### 嵌入式特有危险场景

| 模式 | 示例场景 | 安全影响 |
|------|----------|----------|
| 污点 MMIO 偏移 | `writel(val, mmio + tainted_offset)` | 任意硬件寄存器写入 |
| 污点物理地址 | `dma_map(tainted_paddr, size)` | 任意物理内存访问 |
| 污点 SMC/HVC 参数 | `smc_call(tainted_fnid, tainted_args)` | 安全状态切换绕过 |
| 污点控制权限位 | `set_flags(ctx, tainted_flags)` | 权限提升 |
| 共享内存无校验 | `shm->cmd_id` 未经校验即 dispatch | 任意命令执行 |
| 启动链配置注入 | BL2 解析外部镜像头，字段未校验即使用 | 固件完整性绕过 |
| IPC 消息长度 | `ipc_recv(buf, &len)` len 来自发送方且未校验 | 接收方缓冲区溢出 |

##### 格式化字符串

| 模式 | 示例 | 安全影响 |
|------|------|----------|
| 污点作格式串 | `printf(tainted_fmt, ...)` | 格式化字符串漏洞 |

**自定义函数识别提醒**：存在大量自定义封装函数功能类似上述系统函数，需根据语义识别。

#### 5.2 校验识别清单

##### 显式校验

| 形式 | 示例 | 说明 |
|------|------|------|
| if 边界检查 | `if (idx < MAX)` | 最常见形式 |
| if 范围检查 | `if (addr >= start && addr < end)` | 区间校验 |
| 三元表达式 | `idx = idx < MAX ? idx : 0` | 内联校验 |
| assert/BUG_ON | `BUG_ON(idx >= MAX)` | 仅用于不可恢复检查 |

##### 隐式校验（容易被忽略）

| 形式 | 示例 | 说明 |
|------|------|------|
| switch-case | `switch(val) { case 0: ... }` | 将 val 限制在 case 值集合内 |
| if-else 分支 | `if (type == 0) ... else if (type == 1) ... else return;` | else 分支起到过滤作用 |
| for 循环 | `for(i=0; i<count; i++)` | count 可能在循环体内被间接触发边界限制 |
| 返回值检查 | `if (copy_from_user(...) != 0) return -EFAULT;` | 检查操作成功，间接限制数据 |
| 位运算掩码 | `val = tainted & MASK;` | 隐式截断高位 |
| 类型隐式转换 | `uint8_t v = tainted_uint32;` | 隐式截断，但不可当作可靠校验 |

##### 结构体成员校验分析

- 校验 `s->version` 为特定值后，不代表 `s->data` 被校验
- 校验结构体整体大小 `sizeof(*s)` 不代表内容字段被逐个校验
- 通过已校验字段间接访问成员时，需确认中间字段本身是否也被校验

##### 嵌入式特有校验模式

| 模式 | 说明 |
|------|------|
| 魔数/签名校验 | `if (hdr->magic == EXPECTED_MAGIC)` |
| 硬件状态检查 | `if (REG_READ(STATUS) & READY)` |
| 版本/兼容性字段 | `if (fw_ver >= MIN_VER)` |
| 长度字段交叉校验 | `if (hdr->total_len == hdr->payload_len + HDR_SIZE)` |

#### 5.3 硬性检查门

在判定每一个漏洞之前，必须自问并明确回答以下三个问题：

1. **可触发**：该漏洞是否可以从入口函数的外部输入触发？能否描述完整的触发路径？
2. **未校验**：在污点使用点之前，是否存在上述任何形式的校验（显式或隐式）？**仔细检查隐式校验，宁可误判有校验也不要漏判。**
3. **有安全影响**：是否会导致实际的安全后果（内存破坏、权限提升、信息泄露、代码执行），而不仅仅是稳定性问题？

**三个条件全部满足才上报漏洞。任一条件存疑则不上报。**

### 六、报告输出（步骤5）

#### 输出路径

```
{project_dir}/.ethunter_out/taint-path-checker/{callchainID}_result.md
```

目录不存在时先创建。**必须确保有输出文件**，输出文件是判断 skill 执行成功的依据。

#### 漏洞 ID 生成

格式：`TAINT-{hash8}`

其中 `hash8` = SHA256(`{file_absolute_path}:{function_name}:{begin_line}`) 的前 8 位十六进制字符。

同一 file+func+line 组合产生相同 ID，实现跨任务去重。

#### 无漏洞报告（简洁型）

```markdown
# 污点路径分析报告

- **调用链ID**：593393969
- **分析时间**：2026-06-25 14:30:00
- **结论**：未发现安全漏洞

## 分析摘要

（简述调用链功能、污点数据追踪概况、校验情况）
该调用链中的外部输入均已在关键使用点前经过适当校验，未发现可被利用的安全漏洞。
```

#### 有漏洞报告（详细型）

```markdown
# 污点路径分析报告

- **调用链ID**：593393969
- **分析时间**：2026-06-25 14:30:00
- **结论**：发现 N 个安全漏洞

## 漏洞列表

### 漏洞 TAINT-a1b2c3d4

| 字段 | 内容 |
|------|------|
| **漏洞ID** | TAINT-a1b2c3d4 |
| **严重程度** | 高/中/低 |
| **类型** | Buffer Overflow / OOB Read / ... |
| **所在文件** | /srv/code/driver.c |
| **所在函数** | npu_sem_alloc |
| **关键行号** | 380-385 |
| **是否链外** | 否 |

#### 漏洞描述

（简要描述漏洞本质）

#### 漏洞原理

（详细说明污点数据从入口到漏洞点的完整传播路径，校验缺失的分析过程）

#### 关键代码片段

```c
// 标注出污点变量和危险使用点
```

#### 修复建议

（提出具体的校验方案或防御措施）
```

#### 链外漏洞标记

若发现调用链范围外的漏洞且确认非误报，在漏洞表中标注 `**是否链外**：是`，并在漏洞描述中说明发现途径。

### 七、排除清单与原则

#### 不关注的问题类型

- Memory leaks
- DDoS / resource exhaustion
- Performance issues
- Stability-only issues（无安全影响的崩溃）
- Database / web vulnerabilities
- Privacy / information disclosure without security escalation
- Code style issues or best-practice deviations without security impact
- Race conditions
- Cryptography

#### 核心原则

- 每个漏洞必须从入口函数可以触发
- 污点数据必须未经正确校验
- 错误使用必须导致安全影响，是真实值得修复的漏洞
- 漏洞必须属于调用链范围内（链外漏洞特殊标记）
- **宁可漏报，不要误报**

---

## 技能语言

整个 skill 提示词使用中文，用正式规范用词，避免歧义和逻辑混乱。

## 权限声明

skill 需要提前申请以下工具权限：
- Read：读取源代码文件
- Bash：搜索代码（grep/find）、创建目录
- Write：写入分析报告
