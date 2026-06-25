# 原始需求

## 整体说明

1. 我需要开发一个单纯由markdown文档组成的skill，名字叫taint-path-checker
2. 核心功能：分析一条函数调用链中的全部函数代码，挖掘因外部输入未校验导致的安全问题



## 流程与架构

### 0 工具输入

1. skill使用方法：/taint-path-checker project_dir xxx.json

2. 参数project_dir为待分析项目路径，如果用户没有指定该参数，默认为当前文件夹。注意：当没有传入该参数时，llm不要向用户确认，直接使用当前文件夹作为project_dir

3. 参数xxx.json是一个json格式文件，里面保存了待分析的函数调用链信息。xxx代码callchainID，随着分析任务变化

   ```json
   {
       "callchainID": "593393969",
       "chain":[
           {
               "func": "npu_ioctl_send_request",
               "file": "/srv/code/a.c",
               "begin_line":"213"
           },
           {
               "func": "npu_sem_alloc",
               "file": "/srv/code/a.c",
               "begin_line":"367"
           }
       ]
   }
   ```

   

### 1 获取目标代码

- skill输入的调用链json文件中包含了一条调用链信息（chain字段），每条调用链包含多个函数信息，这里的函数顺序就是调用顺序。第一个函数是入口函数。
- 请从project_dir中，找到每一个函数的源代码，供接下来的分析。如果某个函数源码不存在，请跳过。



### 2 追踪目标参数传递过程

- 我们认为入口函数的参数是外部攻击者可控的外部输入，我们命名为污点数据。
- 分析追踪污点数据在函数调用链间的传递过程。

- 【同名参数区分】：注意，需要分析代码上下文，结合数据流分析污点数据在不同变量间的传递，不要混淆不同作用域下的同名变量。
- 【结构体成员区分】：注意，在污点数据传播过程中，可能需要分析结构体成员的赋值和取值。如果一个结构体变量是污点数据，那么它的每一个成员都是污点数据。相反，如果一个污点数据被赋值给一个结构体的成员，该结构体数据只有被污染的成员是污点数据。



### 2 寻找污点数据的使用点

- 在上一步的污点数据传递过程中，寻找污点数据的使用点。
- 我们关注的使用点包括：污点作为数组索引，污点影响内存读写长度，污点作为指针偏移，污点指针解引用，污点影响控制流等等，这一类使用操作可能引发Buffer overflows ，Out-of-bounds read/write，Use-after-free， Double free，Null pointer dereference, Uninitialized memory access, Integer overflow/underflow，Format string vulnerablities等安全问题

### 3 判断污点是否被正确校验

- 分析上一步找到的污点数据使用点前，代码是否对污点数据进行了正确的校验
- 除了常见的比较判断外，还有很多隐式的校验方式容易被忽略：例如switch-case，if，for等条件判断会限制某些变量的取值；
- 对结构体成员变量的校验需要仔细分析校验影响的范围
- 粗心的校验判断会导致误报



### 4 挖掘外部输入未校验类型问题

- 如果污点数据未经正确校验就被使用，那么很可能造成安全影响，我们需要找到这类安全漏洞
- 我们关注如下Input Validation场景：
  - Interface parameters from userspace (ioctl, sysfs, procfs, device files)
  - IPC data from other components/processors
  - Shared memory data read without integrity or safety checks
  - Trust boundary violations (trusting data from untrusted sources)
  - Missing bounds checking on data from external sources
  - Type confusion from unvalidated input casting
  - Deserialization of untrusted data without validation
  - Environment variable or configuration injection from external sources
- 上述未校验场景中，我们关注如下安全问题：
  - Buffer overflows
  - Out-of-bounds read/write
  - Use-after-free
  - Double free
  - Null pointer dereference
  - Uninitialized memory access
  - Integer overflow/underflow
  - Format string vulnerablities

- 原则：
  - 确保每一个漏洞从入口函数可以触发
  - 确保该污点数据没有被正确校验
  - 确保该污点数据的错误使用会导致安全影响，是一个真实的，值得被修复的安全漏洞
  - 确保漏洞属于skill输入的调用链范围内（如果发现了调用链以外的漏洞，且确定不是误报，在最终输出报告里需要进行特殊标记）
  - 宁可漏报不要误报

### 5 工具输出

1. skill的输出路径为project_dir中的.ethunter_out/taint-path-checker文件夹，如果文件夹不存在，请先创建文件夹
2. 将分析结构生成一份md文档报告，保存在.ethunter_out/taint-path-checker文件夹下，以callchainID+result命名，例如593393969_result.md
3. 如果没有发现安全漏洞，也要生成报告，里面写清楚无安全漏洞
4. 如果发现了安全漏洞，请将漏洞描述，原理，代码范围（文件绝对路径和相关行号，关键代码片段），修复建议记录清楚



## 注意事项

- 注意区分【分析范围】和【漏洞挖掘范围】，整个project_dir中的全部代码都属于分析范围，当需要查找某个函数定义，变量定义时，可以在整个project_dir中浏览查找所需的信息。而漏洞挖掘范围则仅局限于输入的调用链中的函数，我们更关注调用链函数中存在的安全漏洞。

- 我们不关注的问题类型：
  - Memory leaks
  - DDoS / resource exhaustion
  - Performance issues
  - Stability-only issues (crash without security impact)
  - Database / web vulnerabilities
  - Privacy / information disclosure without security escalation
  - Code style issues or best-practice deviations without security impact
  - race conditions
  - cryptography
- 务必确保skill有输出文件，我们需要通过输出文件来判断skill执行是否成功，是否异常中断。

## 要求

1. 需要使用代码仓探索的常用工具，SKILL应提前申请权限。
2. LLM应尽最大努力，精准分析每一个任务，做出最合理的判断。不要牺牲质量来提升效率。
3. 整个skill的提示词都用中文。请使用正式规范用词，避免产生歧义或逻辑混乱
4. 漏洞分析原则：Better to miss some theoretical issues than flood the report with false positives. Each finding should be something a security engineer would confidently raise in a PR review.