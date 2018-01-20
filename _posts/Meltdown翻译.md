# Meltdown

作者：Moritz Lipp,Michael Schwarz,Daniel Gruss,Thomas Prescher,
Werner Haas,Stefan Mangard,Paul Kocher,Daniel Genkin,Yuval Yarom,Mike Hamburg,Graz University of Technology,Cyberus Technology GmbH
,Independent University of Pennsylvania and University of Maryland
,University of Adelaide and Data61,Rambus, Cryptography Research Division

### 摘要

计算机系统的安全主要依赖于内存隔离的机制，例如，内核地址对于用户层是不可访问的。本文中，我们将介绍Meltdown漏洞。Meltdown利用了现代处理器乱序执行的副作用，来读取任意内核空间的内容，包括个人数据和密码。乱序执行目前广泛地应用于现代处理器中。该攻击和操作系统无关，它不依赖于任何软件漏洞