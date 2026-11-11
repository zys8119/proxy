import http from "node:http";
import https from "node:https";
import tls from "node:tls";
import zlib from "node:zlib";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import { URL } from "node:url";
import { execFileSync, execSync } from "node:child_process";

const PORT = Number(process.env.PORT) || 8080;

// ==========================
// 证书管理（HTTPS 中间人拦截）
// ==========================
const CERT_DIR = path.join(process.cwd(), "certs");
const CA_KEY = path.join(CERT_DIR, "ca.key");
const CA_CERT = path.join(CERT_DIR, "ca.crt");
const HOST_DIR = path.join(CERT_DIR, "hosts");
const LOGIN_KEYCHAIN = path.join(
  os.homedir(),
  "Library/Keychains/login.keychain-db",
);

function ensureCA() {
  if (fs.existsSync(CA_KEY) && fs.existsSync(CA_CERT)) return;

  fs.mkdirSync(CERT_DIR, { recursive: true });
  execSync(
    `openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes ` +
      `-keyout "${CA_KEY}" -out "${CA_CERT}" ` +
      `-subj "/CN=Local Proxy CA/O=Local Proxy"`,
    { stdio: "pipe" },
  );
  console.log(`已生成 CA 证书: ${CA_CERT}（信任它才能解密 HTTPS 流量）`);
}

const certCache = new Map<string, { key: string; cert: string }>();

// 叶子证书扩展版本：内容变更时自动重建旧缓存
const HOST_EXT_VERSION = "2";
const HOST_EXT_MARKER = path.join(HOST_DIR, ".ext-version");

// iOS 要求 TLS 服务器证书必须带 EKU serverAuth 和 SAN，否则直接拒绝握手
function hostCertExt(hostname: string): string {
  return [
    "basicConstraints=critical,CA:FALSE",
    "keyUsage=critical,digitalSignature,keyEncipherment",
    "extendedKeyUsage=serverAuth",
    `subjectAltName=DNS:${hostname}`,
    "",
  ].join("\n");
}

// 扩展格式升级后清空旧缓存，保证新签发的证书格式一致
function ensureHostCertFormat() {
  fs.mkdirSync(HOST_DIR, { recursive: true });

  if (
    fs.existsSync(HOST_EXT_MARKER) &&
    fs.readFileSync(HOST_EXT_MARKER, "utf8").trim() === HOST_EXT_VERSION
  ) {
    return;
  }

  for (const file of fs.readdirSync(HOST_DIR)) {
    if (file === ".ext-version") continue;
    fs.rmSync(path.join(HOST_DIR, file), { force: true });
  }

  fs.writeFileSync(HOST_EXT_MARKER, HOST_EXT_VERSION);
}

// 为每个域名签发一张由本地 CA 签名的证书（磁盘缓存）
function getCertPair(hostname: string): { key: string; cert: string } {
  const cached = certCache.get(hostname);
  if (cached) return cached;

  fs.mkdirSync(HOST_DIR, { recursive: true });

  const safeName = hostname.replace(/[^a-zA-Z0-9.-]/g, "_");
  const keyPath = path.join(HOST_DIR, `${safeName}.key`);
  const certPath = path.join(HOST_DIR, `${safeName}.crt`);

  if (!fs.existsSync(keyPath) || !fs.existsSync(certPath)) {
    const csrPath = path.join(HOST_DIR, `${safeName}.csr`);
    const extPath = path.join(HOST_DIR, `${safeName}.ext`);

    fs.writeFileSync(extPath, hostCertExt(hostname));

    execSync(
      `openssl req -new -newkey rsa:2048 -nodes ` +
        `-keyout "${keyPath}" -out "${csrPath}" -subj "/CN=${hostname}"`,
      { stdio: "pipe" },
    );
    execSync(
      `openssl x509 -req -in "${csrPath}" -CA "${CA_CERT}" -CAkey "${CA_KEY}" ` +
        `-CAcreateserial -out "${certPath}" -days 365 -sha256 -extfile "${extPath}"`,
      { stdio: "pipe" },
    );
  }

  const pair = {
    key: fs.readFileSync(keyPath, "utf8"),
    cert: fs.readFileSync(certPath, "utf8"),
  };

  certCache.set(hostname, pair);
  return pair;
}

// 检查本地 CA 是否已被系统信任（按证书本身校验，而不是只看钥匙串里有没有同名证书）
function isCATrusted(): boolean {
  if (process.platform !== "darwin" || !fs.existsSync(CA_CERT)) return false;

  try {
    execFileSync("security", ["verify-cert", "-c", CA_CERT, "-p", "ssl"], {
      stdio: "pipe",
    });
    return true;
  } catch {
    return false;
  }
}

// 未信任时自动把 CA 安装到系统钥匙串并设为信任根（会弹一次系统管理员授权）
function ensureCATrusted() {
  if (process.platform !== "darwin" || isCATrusted()) return;

  const SYSTEM_KEYCHAIN = "/Library/Keychains/System.keychain";

  // 1. 优先装到系统钥匙串，对所有用户和所有 App 生效
  try {
    const script =
      `do shell script "security add-trusted-cert -d -r trustRoot ` +
      `-k ${SYSTEM_KEYCHAIN} " & quoted form of ${JSON.stringify(CA_CERT)} ` +
      `with administrator privileges`;

    execFileSync("osascript", ["-e", script], { stdio: "pipe" });
    console.log("已将本地 CA 安装到系统钥匙串并设为信任根，HTTPS 可直接解密");
    return;
  } catch {}

  // 2. 系统钥匙串安装被取消或失败时，退回当前用户的登录钥匙串
  try {
    execFileSync(
      "security",
      ["add-trusted-cert", "-r", "trustRoot", "-k", LOGIN_KEYCHAIN, CA_CERT],
      { stdio: "pipe" },
    );
    console.log("已将本地 CA 加入登录钥匙串信任，HTTPS 可直接解密");
    return;
  } catch {}

  console.warn(
    "\n本地 CA 尚未被系统信任，请执行一次：\n" +
      `  sudo security add-trusted-cert -d -r trustRoot -k ${SYSTEM_KEYCHAIN} "${CA_CERT}"\n` +
      `临时使用（不安装证书）可加参数：curl --cacert "${CA_CERT}" ...\n`,
  );
}

// ==========================
// CA 下载页（手机等设备安装用）
// ==========================
function getCADer(): Buffer {
  const pem = fs.readFileSync(CA_CERT, "utf8");
  return Buffer.from(
    pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, ""),
    "base64",
  );
}

// 由证书内容派生固定 UUID，保证同一张 CA 重复安装时是同一个描述文件
function caUUID(salt: string): string {
  const h = crypto
    .createHash("sha1")
    .update(getCADer())
    .update(salt)
    .digest("hex");

  return `${h.slice(0, 8)}-${h.slice(8, 12)}-4${h.slice(13, 16)}-a${h.slice(
    17,
    20,
  )}-${h.slice(20, 32)}`.toUpperCase();
}

// iOS 只能通过描述文件 (.mobileconfig) 安装根证书
function buildMobileConfig(der: Buffer): string {
  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>PayloadCertificateFileName</key>
      <string>LocalProxyCA.cer</string>
      <key>PayloadContent</key>
      <data>${der.toString("base64")}</data>
      <key>PayloadDescription</key>
      <string>本地代理根证书（用于 HTTPS 解密）</string>
      <key>PayloadDisplayName</key>
      <string>Local Proxy CA</string>
      <key>PayloadIdentifier</key>
      <string>local.proxy.ca</string>
      <key>PayloadType</key>
      <string>com.apple.security.root</string>
      <key>PayloadUUID</key>
      <string>${caUUID("cert")}</string>
      <key>PayloadVersion</key>
      <integer>1</integer>
    </dict>
  </array>
  <key>PayloadDisplayName</key>
  <string>Local Proxy CA</string>
  <key>PayloadIdentifier</key>
  <string>local.proxy.ca.profile</string>
  <key>PayloadOrganization</key>
  <string>Local Proxy</string>
  <key>PayloadRemovalDisallowed</key>
  <false/>
  <key>PayloadType</key>
  <string>Configuration</string>
  <key>PayloadUUID</key>
  <string>${caUUID("profile")}</string>
  <key>PayloadVersion</key>
  <integer>1</integer>
</dict>
</plist>`;
}

// CA 的 SHA-256 指纹，用于和手机上已安装的证书比对
function caFingerprint(): string {
  const hex = crypto
    .createHash("sha256")
    .update(getCADer())
    .digest("hex")
    .toUpperCase();

  return hex.replace(/(..)(?!$)/g, "$1:");
}

function serveCA(
  pathname: string,
  req: http.IncomingMessage & { headers: Record<string, string> },
  res: http.ServerResponse,
) {
  // 记录是谁来下载证书，便于确认手机是否真的访问过安装页
  const clientIp = String(req.socket.remoteAddress || "").replace(
    /^::ffff:/,
    "",
  );

  console.log(
    `[CA] ${pathname} <- ${clientIp} UA=${String(
      req.headers["user-agent"] || "-",
    )}`,
  );

  if (pathname === "/__ca/ca.mobileconfig") {
    const body = Buffer.from(buildMobileConfig(getCADer()), "utf8");

    res.writeHead(200, {
      "content-type": "application/x-apple-aspen-config",
      "content-disposition": 'attachment; filename="LocalProxyCA.mobileconfig"',
      "content-length": body.length,
    });
    return res.end(body);
  }

  if (pathname === "/__ca/ca.crt" || pathname === "/__ca/ca.cer") {
    const pem = pathname.endsWith(".crt");
    const body = pem ? fs.readFileSync(CA_CERT) : getCADer();

    res.writeHead(200, {
      "content-type": "application/x-x509-ca-cert",
      "content-disposition": `attachment; filename="LocalProxyCA.${
        pem ? "crt" : "cer"
      }"`,
      "content-length": body.length,
    });
    return res.end(body);
  }

  const html = `<!doctype html>
<html lang="zh-CN">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>安装本地代理 CA</title>
<style>
  body{font:16px/1.6 -apple-system,system-ui,sans-serif;margin:24px;max-width:640px;color:#222}
  a{display:inline-block;margin:6px 0;padding:10px 16px;background:#0a84ff;color:#fff;border-radius:8px;text-decoration:none}
  code{background:#f2f2f7;padding:1px 5px;border-radius:4px}
  li{margin:4px 0}
  .fp{font-size:13px;color:#555;word-break:break-all}
</style>
<h1>安装本地代理 CA</h1>
<p>手机必须安装并<strong>信任</strong>这张根证书，代理才能解密 HTTPS，否则会出现
<code>TLS alert certificate unknown</code>。</p>
<p class="fp">SHA-256 指纹：<code>${caFingerprint()}</code><br>
装完后在手机的「信任的凭据」里点开该证书比对指纹；不一致说明装的是别的或旧的 CA。</p>

<h2>iPhone / iPad</h2>
<ol>
  <li><a href="/__ca/ca.mobileconfig">下载描述文件</a></li>
  <li>设置 → 通用 → VPN 与设备管理 → 安装该描述文件</li>
  <li>设置 → 通用 → 关于本机 → 证书信任设置 → 打开 “Local Proxy CA”</li>
</ol>

<h2>Android</h2>
<ol>
  <li><a href="/__ca/ca.cer">下载证书</a></li>
  <li>设置 → 安全 → 加密与凭据 → 安装证书 → CA 证书</li>
  <li>Android 7 起 App 默认不信任用户证书，仅浏览器等部分场景生效</li>
  <li>要让 App 也信任，需 root 后把证书装进系统证书库，或改用可 root 的模拟器（见 README 方案 A）</li>
</ol>

<h2>其他设备</h2>
<p><a href="/__ca/ca.crt">下载 ca.crt（PEM）</a></p>
</html>`;

  res.writeHead(200, {
    "content-type": "text/html; charset=utf-8",
    "content-length": Buffer.byteLength(html),
  });
  res.end(html);
}

// 解压 gzip / deflate / br 响应体
function decodeBody(buffer: Buffer, headers: Record<string, any>): Buffer {
  const encoding = String(headers["content-encoding"] || "").toLowerCase();

  try {
    if (encoding.includes("br")) return zlib.brotliDecompressSync(buffer);
    if (encoding.includes("gzip")) return zlib.gunzipSync(buffer);
    if (encoding.includes("deflate")) return zlib.inflateSync(buffer);
  } catch {}

  return buffer;
}

// Buffer 转换为可读内容
function parseBody(
  buffer: Buffer,
  headers: Record<string, string> | undefined = {},
) {
  const contentType = headers["content-type"] || "";

  if (contentType.includes("application/json")) {
    try {
      return JSON.parse(buffer.toString("utf8"));
    } catch {}
  }

  if (contentType.includes("application/x-www-form-urlencoded")) {
    try {
      return Object.fromEntries(new URLSearchParams(buffer.toString("utf8")));
    } catch {}
  }

  if (
    contentType.includes("text/") ||
    contentType.includes("application/xml") ||
    contentType.includes("application/javascript")
  ) {
    return buffer.toString("utf8");
  }

  return buffer;
}

// 处理请求
async function handleRequest(
  req: http.IncomingMessage & { url: string; headers: Record<string, string> },
  res: http.ServerResponse,
) {
  try {
    // HTTPS 经 MITM 解密后，req.url 只有路径，需要结合 Host 头还原完整地址
    const rawUrl = req.url || "/";

    // 内置 CA 下载页：手机浏览器直接访问代理地址即可安装证书
    const reqPath = rawUrl
      .replace(/^[a-z][a-z0-9+.-]*:\/\/[^/]*/i, "")
      .split("?")[0];

    if (reqPath === "/__ca" || reqPath.startsWith("/__ca/")) {
      return serveCA(reqPath, req, res);
    }

    const isTls = Boolean((req.socket as any).encrypted);
    const protocol = isTls ? "https:" : "http:";

    const target = /^[a-z][a-z0-9+.-]*:\/\//i.test(rawUrl)
      ? new URL(rawUrl)
      : new URL(`${protocol}//${req.headers.host}${rawUrl}`);

    if (!["http:", "https:"].includes(target.protocol)) {
      res.writeHead(400);
      return res.end("Unsupported protocol");
    }

    // 读取完整请求体
    const requestChunks = [];

    for await (const chunk of req) {
      requestChunks.push(chunk);
    }

    const requestBuffer = Buffer.concat(requestChunks);

    const request = {
      method: req.method,
      url: target.href,
      headers: { ...req.headers },
      body: parseBody(requestBuffer, req.headers),
      rawBody: requestBuffer,
    };

    // ==========================
    // 请求拦截点
    // ==========================
    console.log("\n========== REQUEST ==========");
    console.log("Method:", request.method);
    console.log("URL:", request.url);
    console.log("Headers:", request.headers);
    console.log("Body:", request.body);

    // 在这里修改请求
    // request.headers['x-custom'] = 'hello';

    let outgoingBody = requestBuffer;

    if (
      request.headers["content-type"]?.includes("application/json") &&
      request.body &&
      !Buffer.isBuffer(request.body)
    ) {
      outgoingBody = Buffer.from(JSON.stringify(request.body));
    }

    const headers = { ...request.headers } as Record<string, string>;

    delete headers["proxy-connection"];
    delete headers["proxy-authorization"];
    delete headers["connection"];
    delete headers["transfer-encoding"];
    headers.host = target.host;
    headers["content-length"] = outgoingBody.length.toString();

    const transport = (target.protocol === "https:" ? https : http) as any;

    const proxyReq = transport.request(
      {
        hostname: target.hostname,
        port: target.port || undefined,
        path: target.pathname + target.search,
        method: req.method,
        headers,
      },
      async (
        proxyRes: http.IncomingMessage & { headers: Record<string, string> },
      ) => {
        const responseChunks = [];

        for await (const chunk of proxyRes) {
          responseChunks.push(chunk);
        }

        const responseBuffer = decodeBody(
          Buffer.concat(responseChunks),
          proxyRes.headers,
        );

        const response = {
          statusCode: proxyRes.statusCode,
          headers: { ...proxyRes.headers },
          body: parseBody(responseBuffer, proxyRes.headers),
          rawBody: responseBuffer,
        };

        // ==========================
        // 响应拦截点
        // ==========================
        console.log("\n========== RESPONSE ==========");
        console.log("Status:", response.statusCode);
        console.log("Headers:", response.headers);
        console.log("Body:", response.body);

        // 在这里修改响应
        // 例如 JSON 响应增加字段
        if (
          response.headers["content-type"]?.includes("application/json") &&
          response.body &&
          !Buffer.isBuffer(response.body)
        ) {
          response.body.proxy = true;
        }

        let outputBuffer = response.rawBody;

        if (
          response.headers["content-type"]?.includes("application/json") &&
          response.body &&
          !Buffer.isBuffer(response.body)
        ) {
          outputBuffer = Buffer.from(JSON.stringify(response.body));
        }

        // 修改响应后，需要重新计算长度
        const responseHeaders = { ...response.headers } as Record<
          string,
          string
        >;

        delete responseHeaders["transfer-encoding"];
        delete responseHeaders["connection"];
        delete responseHeaders["content-encoding"];
        delete responseHeaders["content-md5"];
        delete responseHeaders.etag;

        responseHeaders["content-length"] = outputBuffer.length.toString();

        res.writeHead(response.statusCode || 502, responseHeaders);

        res.end(outputBuffer);
      },
    );

    proxyReq.on("error", (error: any) => {
      console.error("Proxy error:", error.message);

      if (!res.headersSent) {
        res.writeHead(502);
      }

      res.end("Bad Gateway");
    });

    proxyReq.end(outgoingBody);
  } catch (error) {
    console.error(error);

    if (!res.headersSent) res.writeHead(500);
    res.end("Internal Server Error");
  }
}

ensureCA();
ensureHostCertFormat();
ensureCATrusted();

// MITM 服务器：接收 CONNECT 后的原始连接，完成 TLS 握手并按 SNI 动态签发证书
const defaultCert = getCertPair("localhost");

const mitmServer = https.createServer(
  {
    key: defaultCert.key,
    cert: defaultCert.cert,
    SNICallback: (servername, callback) => {
      try {
        callback(null, tls.createSecureContext(getCertPair(servername)));
      } catch (error) {
        callback(error as Error);
      }
    },
  },
  handleRequest as any,
);

mitmServer.on("tlsClientError", (error: Error, socket: any) => {
  console.error("TLS 握手失败:", error.message);

  if (error.message.includes("certificate unknown")) {
    const ip = Object.values(os.networkInterfaces())
      .flat()
      .find((info) => info?.family === "IPv4" && !info.internal)?.address;

    console.error(
      `客户端不信任本地 CA，请在该设备浏览器打开 http://${ip}:${PORT}/__ca 安装并信任证书`,
    );
  }

  socket.destroy();
});

const server = http.createServer(handleRequest as any);

// 处理 HTTPS 的 CONNECT 请求：解密后复用同一套请求/响应拦截逻辑
server.on("connect", (req, clientSocket, head) => {
  const [hostname, port = "443"] = String(req.url).split(":");

  console.log("\n========== CONNECT ==========");
  console.log("Target:", `${hostname}:${port}`);
  console.log(
    "Client:",
    String((clientSocket as any).remoteAddress || "").replace(/^::ffff:/, ""),
  );

  clientSocket.write("HTTP/1.1 200 Connection Established\r\n\r\n");

  if (head && head.length) {
    clientSocket.unshift(head);
  }

  mitmServer.emit("connection", clientSocket);
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`Proxy listening on http://0.0.0.0:${PORT}`);

  const lanIps = Object.values(os.networkInterfaces())
    .flat()
    .filter((info) => info?.family === "IPv4" && !info.internal)
    .map((info) => info!.address);

  for (const ip of lanIps) {
    console.log(`Proxy listening on http://${ip}:${PORT}`);
    console.log(`手机安装 CA（浏览器打开）: http://${ip}:${PORT}/__ca`);
  }
  try {
    execFileSync(`x qr  http://${lanIps[0]}:${PORT}/__ca`, {
      stdio: "inherit",
      shell: true,
    });
  } catch (error: any) {
    /// 忽略错误
  }
});
