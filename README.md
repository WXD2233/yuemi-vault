# 钥密 · 自托管密码管理器

钥密是一套独立运行在 Linux VPS 上的中文密码管理器，支持密码生成、完整记录加密、设备管理、邮箱二次验证、离线恢复密钥，以及 Chrome / Edge 密码导入和加密备份。

项目只包含 Node.js、SQLite 与 Docker/VPS 部署，不包含 Cloudflare 或 Sites 配置。

## Docker 版本（服务器已安装 Docker）

如果服务器已经有 Docker Engine 与 Docker Compose，直接克隆项目并运行：

```bash
git clone https://github.com/WXD2233/yuemi-vault.git
cd yuemi-vault
bash docker-start.sh
```

脚本会为当前服务器生成独立的随机初始主密码和 `SMTP_CONFIG_KEY`，构建精简运行镜像，并只启动应用容器。默认地址是：

```text
http://127.0.0.1:51213
```

该模式不会启动项目内置 Caddy，也不会占用 80/443。请让服务器已有的 Nginx、Caddy、Traefik、宝塔或 1Panel 通过 HTTPS 反向代理到上述地址。

也可以手动复制配置并启动：

```bash
cp docker.env.example .env
openssl rand -hex 12
openssl rand -hex 32
# 把上面两条命令的结果分别填入 .env
chmod 600 .env
docker compose up -d --build app
```

每次推送到 `main` 或创建 `v*` 标签时，GitHub Actions 还会构建 `linux/amd64` 与 `linux/arm64` 镜像并发布到：

```text
ghcr.io/wxd2233/yuemi-vault:latest
```

要使用预构建镜像，在 `.env` 中设置 `YUEMI_IMAGE=ghcr.io/wxd2233/yuemi-vault:latest`，然后执行：

```bash
docker compose pull app
docker compose up -d --no-build app
```

GitHub 容器包需要设为公开才能匿名拉取；私有包需要先执行 `docker login ghcr.io`。

## VPS 一键安装

支持 64 位 Ubuntu 22.04/24.04/26.04 和 Debian 12/13。安装脚本会从 Docker 官方软件源安装 Docker Engine 与 Compose、下载项目、生成每台服务器独有的安全密钥、构建容器并启动服务。

### VPS 已有 HTTPS 服务（推荐）

如果服务器已有 Nginx、Caddy、Traefik、宝塔或 1Panel，请不要向脚本传域名：

```bash
curl -fsSL https://raw.githubusercontent.com/WXD2233/yuemi-vault/main/install-vps.sh -o install-vps.sh
sudo bash install-vps.sh
```

钥密默认只监听 `127.0.0.1:51213`，不会占用公网 80/443，也不需要放行 51213。让现有 HTTPS 服务把独立域名反向代理到：

```text
http://127.0.0.1:51213
```

Nginx 示例（证书部分继续使用你现有的配置）：

```nginx
location / {
    proxy_pass http://127.0.0.1:51213;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $remote_addr;
    proxy_set_header X-Forwarded-Proto https;
    client_max_body_size 25m;
}
```

必须通过 HTTPS 域名访问。不要把主密码通过公网 HTTP 发送，也不要把 51213 端口直接开放到公网。

### 独立 VPS、由钥密自动申请 HTTPS

只有在 VPS 的 80/443 没有被其他服务占用时，才把域名传给脚本：

```bash
sudo bash install-vps.sh vault.example.com
```

先把域名 A/AAAA 记录指向 VPS，并放行 TCP 80、TCP/UDP 443。脚本会启用项目自带的 Caddy，自动申请并续期证书。若 80 或 443 已被占用，安装会发生端口冲突，此时请改用上一节的“已有 HTTPS 服务”方式。

## 首次登录

安装脚本会生成随机初始主密码，并只在安装完成时显示一次。请立即保存它：

1. 使用脚本显示的随机初始主密码登录。
2. 首次进入必须设置新的主密码；未完成就关闭页面，下次仍按首次进入处理。
3. 新主密码为 10–128 位，至少包含大写字母、小写字母、数字和符号中的三类。
4. 设置通知邮箱与 SMTP，发送测试邮件后再开启新设备二次验证。
5. 生成并下载离线恢复密钥，保存到另一台设备或离线介质。

验证码每次随机生成、10 分钟有效且只能使用一次。服务器不会通过邮件发送或重置明文主密码；找回时必须同时通过邮箱验证码，并在浏览器本地使用离线恢复密钥解密。

## 数据与加密

- 应用：Node.js 24 + Vinext
- 数据库：本地 SQLite，WAL 模式
- 持久化：Docker 卷 `yuemi-vault_vault_data`
- 记录加密：PBKDF2-SHA-256（新记录 600,000 次）+ AES-256-GCM
- 主密码校验：每个数据库独立随机盐值，PBKDF2-SHA-256 600,000 次
- SMTP 授权码：使用服务器 `.env` 中独立随机密钥进行 AES-GCM 加密
- 备份：浏览器本地使用主密码加密，服务器只接收记录密文

旧版记录和旧版主密码哈希可以继续读取；新建记录或修改主密码后会使用新的加密参数。只启动一个应用副本，不要让多个实例同时写入同一个 SQLite 数据卷。

## 常用管理命令

```bash
cd /opt/yuemi-vault
sudo docker compose ps
sudo docker compose logs -f app
sudo docker compose up -d --build
sudo docker compose restart
sudo docker compose down
```

使用项目自带自动 HTTPS 时，在 Compose 命令中加入：

```bash
sudo docker compose --profile standalone-https up -d --build
```

`docker compose down` 不会删除密码数据。不要执行 `docker compose down -v`，因为 `-v` 会永久删除密码数据库卷。

## 手动部署

```bash
git clone https://github.com/WXD2233/yuemi-vault.git
cd yuemi-vault
openssl rand -hex 12
openssl rand -hex 32
```

把两次输出分别填入以下文件，然后启动：

```dotenv
SITE_ADDRESS=:80
BIND_ADDRESS=127.0.0.1
HTTP_PORT=51213
YUEMI_INITIAL_PASSWORD=第一条随机值
SMTP_CONFIG_KEY=第二条随机值
```

```bash
chmod 600 .env
docker compose up -d --build app
```

生产环境缺少 `YUEMI_INITIAL_PASSWORD` 或 `SMTP_CONFIG_KEY` 时会拒绝启动，防止所有安装共用公开密码或无法安全保存 SMTP 授权码。

## 本地开发

需要 Node.js 22.13.0 或更高版本：

```bash
npm ci
npm run dev
npm run lint
npm test
npm run security:audit
```

本地非生产开发在未设置环境变量时可使用开发初始密码 `12345678`。该回退不会在 `NODE_ENV=production` 中启用。

## 主要功能

- 生成 2–30 位密码，可组合数字、大小写字母和特殊符号
- 保存、查看、复制、修改和搜索密码记录，支持自定义分类
- 账号、密码、备注和分类整体加密，服务器只保存密文
- 每次进入都由服务端重新校验主密码
- 可选的新设备随机邮箱验证码和不可伪造的设备凭证
- 可配置错误次数、锁定时间和浏览器空闲自动锁定
- 管理并删除已加入设备，删除后立即撤销该设备会话
- 支持任意正确配置且解析到公网地址的 SMTP 服务
- 导入 Chrome / Edge 明文 CSV，并在浏览器内加密后上传
- 导入、导出 AES-GCM 加密密码备份
- 多主题和手机屏幕自适应

## 安全提示

- 不要提交 `.env`、数据库文件、SMTP 授权码、恢复密钥或真实密码到 GitHub。
- Chrome / Edge 导出的 CSV 是明文，导入后应立即安全删除。
- 恢复密钥不要和 VPS 数据库备份放在同一位置。
- 定期导出加密备份，并在另一台设备验证可以解密。
- 只开放 SSH 与现有 HTTPS 服务实际需要的端口。
- 修改主密码会重新加密所有记录、清除恢复材料并撤销全部登录会话；重新登录后要生成新的恢复密钥。
