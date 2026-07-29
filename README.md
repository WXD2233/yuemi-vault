# 钥密 · 安全密码管理器

钥密是一套支持密码生成、加密记录、设备管理、邮箱验证与加密备份的密码管理器。项目使用 Vinext、React、Cloudflare D1 和 AES-GCM 构建。

线上版本：[打开钥密](https://yuemi-vault-2026.workspace-387364.chatgpt.site)

## 主要功能

- 生成 2–30 位密码，可组合数字、大小写字母和特殊符号
- 保存、查看、修改和搜索密码记录
- 自定义密码分类与推荐分类
- 所有设备每次进入都由服务端重新校验
- 新设备邮箱二次验证，可在设置中关闭
- 可配置密码错误次数和锁定时间
- 管理并删除已加入的设备
- 支持任意正确配置的 SMTP 邮箱服务
- 导入 Chrome、Edge 导出的密码 CSV
- 导出和恢复 AES-GCM 加密密码备份
- 深色、浅色、紫罗兰、冰川和琥珀主题
- 桌面端与手机端自适应

## Windows 一键安装

### 方法一：双击安装

1. 在 GitHub 页面点击 **Code → Download ZIP**。
2. 完整解压 ZIP 文件。
3. 双击 `install.cmd`。
4. 安装完成后双击 `start.cmd`。
5. 在浏览器打开启动窗口中显示的 `Local` 地址。

安装脚本会自动完成：

- 检查 Node.js `22.13.0` 或更高版本
- 缺少 Node.js 时通过 Windows `winget` 安装 Node.js LTS
- 安装锁定版本的项目依赖
- 执行完整生产构建

### 方法二：使用 Git

```powershell
git clone https://github.com/WXD2233/yuemi-vault.git
cd yuemi-vault
.\install.cmd
```

完成后运行：

```powershell
.\start.cmd
```

## 首次登录

- 默认主密码：`12345678`
- 首次进入后必须立即设置新的主密码
- 未完成修改就刷新、关闭或重新打开时，需要从首次登录重新开始
- 演示固定验证码：`246810`

新主密码需要 10–128 位，并至少包含大写字母、小写字母、数字和符号中的三类。

## 手动安装

需要 Node.js `22.13.0` 或更高版本。

```bash
npm ci
npm run build
npm run dev
```

## 常用命令

```bash
npm run dev          # 启动本地开发服务器
npm run build        # 创建生产构建
npm test             # 构建并运行测试
npm run lint         # 代码检查
npm run db:generate  # 生成 D1 数据库迁移
```

## 安全提示

- 不要把真实密码、SMTP 授权码或 `.env` 文件提交到 GitHub。
- Chrome 和 Edge 导出的原始 CSV 是明文文件，导入完成后应及时删除。
- 加密备份恢复时必须输入创建备份时使用的主密码。
- 修改主密码会重新加密密码记录，并使所有已登录设备的会话失效。

## 项目结构

- `app/`：界面与 API 路由
- `db/`：数据库、会话与加密配置
- `drizzle/`：D1 数据库迁移
- `tests/`：构建和功能检查
- `install.cmd`：Windows 一键安装入口
- `install.ps1`：安装检查与执行逻辑
- `start.cmd`：Windows 本地启动入口
