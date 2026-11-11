import http from "node:http";
import https from "node:https";
import tls from "node:tls";
import zlib from "node:zlib";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { URL } from "node:url";
import { execFileSync, execSync } from "node:child_process";

const PORT = 8080;

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

    fs.writeFileSync(extPath, `subjectAltName=DNS:${hostname}\n`);

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
  socket.destroy();
});

const server = http.createServer(handleRequest as any);

// 处理 HTTPS 的 CONNECT 请求：解密后复用同一套请求/响应拦截逻辑
server.on("connect", (req, clientSocket, head) => {
  const [hostname, port = "443"] = String(req.url).split(":");

  console.log("\n========== CONNECT ==========");
  console.log("Target:", `${hostname}:${port}`);

  clientSocket.write("HTTP/1.1 200 Connection Established\r\n\r\n");

  if (head && head.length) {
    clientSocket.unshift(head);
  }

  mitmServer.emit("connection", clientSocket);
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`Proxy listening on http://0.0.0.0:${PORT}`);
  console.log(
    execSync(`x ip | awk '{print $3}'`)
      .toString()
      .split("\n")
      .filter((e: any) => /^192/.test(e))
      .map((e: any) => `Proxy listening on http://${e.trim()}:${PORT}`)
      .join("\n"),
  );
});
