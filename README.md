方案 A：把证书放进系统证书库（需 root，最可靠）

Android 要求文件名是证书 subject 的 hash（`.0` 后缀），PEM 格式、`root:root` 、权限 644：

Bash

运行

1
2
3
4
5
6
7

`# 1. 算文件名（macOS 自带 LibreSSL 也支持）
openssl x509 -inform PEM -subject_hash_old -in certs/ca.crt | head -1
# 假设输出 3f8a2c1b，则文件名为 3f8a2c1b.0
cp certs/ca.crt 3f8a2c1b.0

# 2. 推送到手机
adb push 3f8a2c1b.0 /sdcard/`

- Android ≤ 9：`adb shell su -c "mount -o rw,remount /system && cp /sdcard/3f8a2c1b.0 /system/etc/security/cacerts/ && chmod 644 /system/etc/security/cacerts/3f8a2c1b.0 && reboot"`
- Android 10+：系统分区只读，手动 cp 会失败，用 Magisk 模块把用户证书搬到系统库（推荐现成模块`AlwaysTrustUserCerts` /`MagiskTrustUserCerts` ），装完重启；比手改安全、能扛 OTA。
- Android 14+：系统库实际在`/apex/com.android.conscrypt/cacerts` ，用上述 Magisk 模块（新版已适配），别手工往`/system/etc/security/cacerts` 放。
装好后到 设置 → 安全 → 加密与凭据 → 信任的凭据，切到「系统」标签页能看到`Local Proxy CA` 才算成功。

方案 B：无 root 的替代

- 改包：`apktool` 反编译，加`res/xml/network_security_config.xml` （`<certificates src="user"/>` ）并在 manifest 引用，重签名安装。App 有加固/签名校验（抖音系基本都有）时不可行。
- 在 root 过的模拟器/云手机里跑 App，同样按方案 A 把证书装进系统库。
- 如果目标只是看流量不是模拟请求，可以只分析浏览器侧的请求。
方案 C：App 仍然报 46，说明还有证书固定（pinning）

先确认是不是 pinning：

```bash
adb logcat -c && adb logcat | grep -iE "pin|trust anchor|SSLPeerUnverified|certificate"
```

- `Trust anchor for certification path not found` → 还是信任问题，回方案 A
- `Certificate pinning failure` / `Pin verification failed` → 确认是 pinning，继续往下

C1. root + Frida（通用方案）

```bash
# 1. 版本要一致：PC 端与手机端 frida 必须同版本
pip3 install --upgrade frida-tools
frida --version

# 2. 从 https://github.com/frida/frida/releases 下载对应架构的 frida-server
adb push frida-server /data/local/tmp/
adb shell "su -c 'chmod 755 /data/local/tmp/frida-server'"
adb shell "su -c '/data/local/tmp/frida-server &'"
frida-ps -U        # 能列出进程说明通了

# 3. 找包名
adb shell pm list packages | grep -iE "douyin|qishui"
```

跑现成的 unpinning 脚本（覆盖 OkHttp `CertificatePinner`、`TrustManagerImpl`、Conscrypt、Cronet、TrustKit）：

```bash
frida -U -f <包名> -l https://codeshare.frida.re/@pcipolloni/universal-android-ssl-pinning-bypasser/ --no-pause
# 或用 HTTP Toolkit 的脚本集 frida-interception-and-unpinning
```

C2. 抖音/汽水音乐这类（Cronet / native 校验）

它们的 pinning 在 `libcronet` 的 BoringSSL 里，Java 层 hook 一般无效，需要 hook native 导出符号：

- `SSL_CTX_set_custom_verify`
- `X509_VERIFY_PARAM_set1_host` / `X509_VERIFY_PARAM_set1_ip_asc`
- `SSL_get_verify_result`（强制返回 0）

更省事的做法是用 r0capture 直接在 `SSL_read` / `SSL_write` 取明文，不依赖信任链和 pinning：

```bash
python3 r0capture.py -U -f <包名> -p out.pcap
```

C3. 不用 Frida 的替代

- LSPosed 模块：`TrustMeAlready`、`JustTrustMe++`（只对 Java 层 pinning 有效）
- objection：`pip3 install objection` → `objection -g <包名> explore` → `android sslpinning disable`

C4. 仍然失败时

- 抖音系带 Frida 反调试（扫线程名/端口/maps）：把 `frida-server` 改名、`-l 0.0.0.0:1234` 换端口，配合 Magisk + Zygisk + Shamiko 隐藏 root。
- 加固壳可能在 native 层再校验一遍，只能走内核层抓包（eBPF/pcap）绕过。
- 仅在自己持有并授权的设备和账号上调试。

补充：Android 要求服务器证书 RSA ≥ 2048、SHA-256、带 SAN，你现在签发的证书这些条件都满足（`basicConstraints` /`keyUsage` /`EKU serverAuth` 已在上一轮补齐），装进系统库后即可正常握手。