# 钥密 · 自托管密码管理器

钥密支持密码生成、加密记录、设备管理、SMTP 邮箱验证和加密备份，是一套完全独立运行在 Linux VPS 上的自托管服务。

## VPS 一键安装

支持 64 位 Ubuntu 22.04/24.04/26.04 和 Debian 12/13。脚本会通过 Docker 官方软件源安装 Docker Engine 与 Compose，下载项目、构建容器并启动 Caddy 反向代理。

### 有域名（推荐，自动 HTTPS）

先把域名 A/AAAA 记录指向 VPS，然后执行：

```bash
curl -fsSL https://raw.githubusercontent.com/WXD2233/yuemi-vault/main/install-vps.sh -o install-vps.sh
sudo bash install-vps.sh vault.example.com
```

安装后访问 `https://vault.example.com`。Caddy 会自动申请并续期 HTTPS 证书。

### 没有域名（使用 VPS IP）

```bash
curl -fsSL https://raw.githubusercontent.com/WXD2233/yuemi-vault/main/install-vps.sh -o install-vps.sh
sudo bash install-vps.sh
```

安装后访问 `http://VPS-IP:51213`。默认不占用宿主机的 80 端口，需要在云厂商安全组或 VPS 防火墙中放行 TCP 51213；使用项目自带的域名自动 HTTPS 时还需要放行 TCP/UDP 443。

如果 VPS 已有 Nginx、Caddy、Traefik、宝塔或 1Panel 管理 HTTPS，建议继续由现有服务负责证书，把域名反向代理到 `http://127.0.0.1:51213`，不要让两个服务同时占用 443 端口。

> 私有仓库无法匿名下载脚本。可先使用有权限的账号克隆仓库，再在仓库目录执行 `sudo bash install-vps.sh [域名]`。

## 首次登录

- 默认主密码：`12345678`
- 首次登录后必须立即修改主密码；未完成修改就关闭或刷新页面，下次仍按首次进入处理
- 演示固定验证码：`246810`

正式使用前务必修改默认主密码，并配置真实通知邮箱和 SMTP。

## VPS 架构与数据

- 应用：Node.js 24 + Vinext
- 数据库：VPS 本地 SQLite（WAL 模式）
- 入口：Caddy 2，域名模式自动提供 HTTPS
- 持久化：Docker 卷 `yuemi-vault_vault_data`
- SMTP：使用 Node TLS/STARTTLS，可连接任意配置正确的邮箱服务商

密码记录仍由应用使用主密码派生的密钥加密；SQLite 文件、SMTP 配置及其他服务数据均保存在 VPS 数据卷中。只启动一个应用副本，不要对同一个 SQLite 数据卷横向扩容。

### 常用管理命令

```bash
cd /opt/yuemi-vault
sudo docker compose ps
sudo docker compose logs -f app
sudo docker compose up -d --build
sudo docker compose restart
sudo docker compose down
```

`docker compose down` 不会删除密码数据。不要运行 `docker compose down -v`，因为 `-v` 会删除数据卷。

## 手动部署 VPS 版

```bash
git clone https://github.com/WXD2233/yuemi-vault.git
cd yuemi-vault
printf 'SITE_ADDRESS=:80\nHTTP_PORT=51213\nHTTPS_PORT=443\n' > .env
docker compose up -d --build
```

`SITE_ADDRESS=:80` 是 Caddy 在容器内部监听的端口，宿主机对外使用 `51213`，因此不会占用 VPS 的 80 端口。使用域名时，把 `.env` 中的 `SITE_ADDRESS=:80` 改成自己的域名。

## 本地开发

需要 Node.js `22.13.0` 或更高版本：

```bash
npm ci
npm run dev
```

项目只有 Node/VPS 构建，不包含任何 Cloudflare 或 Sites 部署配置：

```bash
npm run build
npm run start
```

默认 VPS 数据目录为项目下的 `data/`，可通过 `YUEMI_DATA_DIR` 或 `YUEMI_DATABASE_PATH` 修改。

## 主要功能

- 生成 2–30 位密码，可组合数字、大小写字母和特殊符号
- 保存、查看、修改、搜索和自定义分类
- 所有设备每次进入时由服务端重新校验
- 可选的新设备邮箱二次验证
- 可配置错误次数和锁定时间，并管理已加入设备
- 支持任意正确配置的 SMTP 服务
- 导入 Chrome/Edge 密码 CSV
- 导入和导出 AES-GCM 加密密码备份
- 多主题和手机屏幕自适应

## 安全提示

- 不要把真实密码、SMTP 授权码、`.env` 或数据库文件提交到 GitHub
- Chrome/Edge 导出的 CSV 是明文文件，导入完成后应及时安全删除
- 定期使用应用中的“导出加密备份”功能，并把备份保存到另一台设备
- VPS 应及时安装系统和 Docker 安全更新，只开放 SSH、51213 和 443 等实际需要的端口
- 修改主密码会重新加密密码记录，并使所有已有会话失效
