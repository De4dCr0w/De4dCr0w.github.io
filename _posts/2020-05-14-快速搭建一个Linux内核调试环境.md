---

layout: post

title: '快速搭建一个Linux内核调试环境'

date: '2020-05-14'

header-img: "img/home-bg.jpg"

tags:
     - kernel debug 
author: 'De4dCr0w'

---

<!-- more -->

### 内核源码下载

内核源码下载渠道：

（1）git clone 内核，在git checkout某一个分支：git clone https://github.com/torvalds/linux.git 适用于git commit补丁前的漏洞调试

（2）https://cdn.kernel.org/pub/linux/kernel/v4.x/ 适用于4.x.x版本的内核，下不到更小的发行版

（3）sudo apt-get source linux-image-$(uname -r) 下载当前内核版本或更小的发行版，缺点：版本不全

一般选择方式1，找到漏洞引入的commit，切换过去。或者切到漏洞补丁的commit，然后将补丁手动注释。

也可以下载http://security.ubuntu.com/ubuntu/pool/main/l/linux/ 中的linux-image-*-*amd64.deb包，解压里面有bzImage，如果能找到对应的vmlinux带符号镜像，那就可以直接调了，不然要想打断点调试，就得编译内核来获取镜像。

### 编译内核

```
make defconfig
make menuconfig
make -j8
```

（1）先make defconfig，获取默认的config，这样的config配置少，可以极大提高编译速度，一般几分钟就好了。

（2）要进行打断点调试，需要关闭系统的随机化和开启调试信息：

```
Processor type and features  ---> 
    [ ] Build a relocatable kernel                                               
        [ ]  Randomize the address of the kernel image (KASLR) (NEW) 


Kernel hacking  --->
    Compile-time checks and compiler options  --->  
        [*] Compile the kernel with debug info                                                                  
        [ ]   Reduce debugging information                                                                      
        [ ]   Produce split debuginfo in .dwo files                                                             
        [*]   Generate dwarf4 debuginfo                                         
        [*]   Provide GDB scripts for kernel debugging  
```

（3）进行编译，根据cpu数进行多线程编译，提高速度

如果要用到userfaultfd、ebpf的系统调用，需要在编译选项中开启：

```
 General setup  --->  
    [*] Enable bpf() system call                                                
    [*] Enable userfaultfd() system call     
```

### 下载文件系统镜像

（1）如果漏洞不涉及很多模块，较为简单的就是下载一个ctf kernel pwn的镜像文件，对镜像文件rootfs.img 进行解包修改：

```
mkdir core
mv rootfs.img ./core/rootfs.cpio.gz 
cd core
gunzip rootfs.cpio.gz
cpio -idmv < rootfs.cpio
rm -rf rootfs.cpio
```
将漏洞exp放入，再重新打包：

```
find . | cpio -o --format=newc > ../rootfs.img
```

(2) 涉及较为复杂的模块，如网络，驱动，或者应用层组件，可以获取下面的镜像：


```
sudo apt-get install debootstrap
wget https://raw.githubusercontent.com/google/syzkaller/master/tools/create-image.sh -O create-image.sh
chmod +x create-image.sh
./create-image.sh
```

配置网络上网，下载Exp到系统中：

```
将/etc/network/interfaces中设置成dhcp,将eth0 改成ip addr 显示的网卡:
auto eth0
iface eth0 inet dhcp
重启网络服务:/etc/init.d/networking restart

```

此时qemu可以访问外网，host还不能和qemu通信，所以配置下guest与 host 通信。

#### 配置 guest与 host 通信

使用tap方式上网：

a、host主机上的配置：

```
sudo apt-get install uml-utilities
sudo apt-get install bridge-utils

sudo ifconfig ens33 down              
sudo brctl addbr br0                      
sudo brctl addif br0 ens33            
sudo brctl stp br0 off                 
sudo brctl setfd br0 1                 
sudo brctl sethello br0 1              
sudo ifconfig br0 0.0.0.0 promisc up      
sudo ifconfig ens33 0.0.0.0 promisc up      
sudo dhclient br0
sudo brctl show br0
sudo brctl showstp br0

sudo ip tuntap add mode tap user $(whoami)
sudo tunctl -t tap0 -u root    
sudo brctl addif br0 tap0
sudo ifconfig tap0 0.0.0.0
sudo brctl showstp br0

删除tap0
sudo tunctl -d tap0
```

b、qemu虚拟机上的配置：

```
设置ssh登陆：
sudo vim /etc/pam.d/sshd
注释下面两处，运行root和普通用户ssh登陆：

# Disallow non-root logins when /etc/nologin exists.
#account    required     pam_nologin.so


# Uncomment and edit /etc/security/access.conf if you need to set complex
# access limits that are hard to express in sshd_config.
# account  required     pam_access.so

sudo /etc/init.d/ssh start  #启动ssh
```

### 启动qemu进行漏洞调试

qemu 启动脚本：

```
sudo qemu-system-x86_64 \
    -m 2G \
    -smp 2 \
    -kernel ./bzImage \
    -append "console=ttyS0 root=/dev/sda earlyprintk=serial"\
    -drive file=./stretch.img,format=raw \
    -net nic \
    -net tap,ifname=tap0,script=no,downscript=no \
    -enable-kvm \
    -nographic \
    -pidfile vm.pid \
    2>&1 | tee vm.log
```

由于设置为tap方式，host和qemu在同一个网段里，同时其他host虚拟机也可以进行ssh连接qemu

默认登陆的是root用户，添加sudo 用户：

```
adduser pwn
usermod -aG sudo pwn
```

### 参考链接

https://blog.csdn.net/scarecrow_byr/article/details/17741133

https://github.com/google/syzkaller/blob/master/docs/linux/setup_ubuntu-host_qemu-vm_x86-64-kernel.md

