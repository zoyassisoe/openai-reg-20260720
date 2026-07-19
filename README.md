# openai-reg-20260720

OpenAI / ChatGPT 批量注册 + TOTP 2FA + 接码绑手机 + RT 导出操作台。

项目已包含 Dockerfile 和 Docker Compose 配置，推荐直接使用 Docker Compose 部署。

## 功能

- API URL、密码 IMAP、Outlook OAuth 邮箱取码
- 批量注册和唯一姓名分配
- 注册与 TOTP 2FA 固定作为一个任务执行
- 查看、复制和刷新 AT
- 在凭据页实时获取、复制或下载完整 Session JSON
- 注册完成后使用 SmsBower / HeroSMS 单个或批量绑定手机号
- 绑号成功后自动拉取 Codex RT，并落盘成功凭证
- 一键导出 Sub2API 格式 RT JSON（默认）；也支持 rtjson / 纯 RT
- 任务归档、左侧自定义分类、账号备注
- 套餐识别（free/plus 等），按最新 session/成功凭证来源判定
- 现有会话失效后使用邮箱验证码登录；远端已开启 2FA 且本地无密钥时，可走平台提供的邮箱恢复验证
- 单个代理和代理 IP 池
- 顺序轮询、随机选择、账号固定、固定第一个
- 检测本机公网 IP、代理出口 IP、国家、地区、城市和运营商
- 批量删除、重试和导出账号凭据
- 注册任务分页和跨页批量选择

导出格式：

```text
email----password----url----2fa Secret----at
```

RT 导出（默认 Sub2API）：

```text
GET /api/export/rt?format=sub2api&phoneBoundOnly=1
```

可选 `format`：

- `sub2api`（默认）：Sub2API accounts 数组 JSON
- `rtjson` / `cpa`：Codex token JSON，NDJSON 每行一个
- `rt`：纯 refresh_token，每行一个

## 最简单部署

### 1. 安装 Docker

Ubuntu：

```bash
sudo apt update
sudo apt install -y docker.io docker-compose-v2
sudo systemctl enable --now docker
sudo usermod -aG docker "$USER"
```

执行后重新登录 SSH，确认 Docker 可用：

```bash
docker version
docker compose version
```

Windows 或 macOS 安装 Docker Desktop 即可。

### 2. 创建配置

进入项目目录：

```bash
cd openai-reg-20260720
cp .env.example .env
```

编辑 `.env`：

```dotenv
REG_2FA_USERNAME=admin
REG_2FA_PASSWORD=请换成足够长的随机密码
REG_2FA_PUBLIC_PORT=5190
TZ=Asia/Shanghai
```

Ubuntu 可以生成随机密码：

```bash
openssl rand -base64 32
```

### 3. 一条命令构建并启动

```bash
docker compose --env-file .env -f compose.yml up -d --build
```

启动后访问：

```text
http://127.0.0.1:5190
```

使用 `.env` 中设置的用户名和密码登录。

## 检查运行状态

```bash
docker compose --env-file .env -f compose.yml ps
```

健康检查：

```bash
curl http://127.0.0.1:5190/api/health
```

正常响应：

```json
{"ok":true,"service":"registration-2fa"}
```

查看日志：

```bash
docker compose --env-file .env -f compose.yml logs -f --tail=200
```

## 更新项目

更新代码后重新执行：

```bash
docker compose --env-file .env -f compose.yml up -d --build --force-recreate
```

如需完全忽略镜像缓存：

```bash
docker compose --env-file .env -f compose.yml build --no-cache
docker compose --env-file .env -f compose.yml up -d --force-recreate
```

## 停止和重启

停止服务：

```bash
docker compose --env-file .env -f compose.yml down
```

重启服务：

```bash
docker compose --env-file .env -f compose.yml restart
```

不要执行下面的命令：

```bash
docker compose --env-file .env -f compose.yml down -v
```

`-v` 会删除账号密码、登录态、TOTP Secret、AT 和任务数据。

## Ubuntu 远程访问

Compose 默认只监听服务器本机的 `127.0.0.1:5190`，不会直接暴露到公网。

临时访问可使用 SSH 隧道。在自己的电脑执行：

```bash
ssh -L 5190:127.0.0.1:5190 用户名@服务器IP
```

然后打开：

```text
http://127.0.0.1:5190
```

长期使用建议通过 Nginx 反向代理到 `http://127.0.0.1:5190`，并配置 HTTPS。不要直接把未加密的管理面板端口暴露到公网。

## 数据位置

持久化数据保存在 Docker 数据卷：

```text
imap-registration-2fa_registration_2fa_data
```

容器重新构建或执行普通的 `docker compose down` 不会删除数据。

## 代理池

代理池支持每行一个代理：

```text
http://user:password@host:port
host:port
host:port:user:password
socks5h://host:port
```

建议先点击“检测代理出口 IP”，确认代理可用后再保存并启动任务。

代理策略：

- 顺序轮询：任务依次使用代理池中的代理
- 随机选择：每个任务随机选择代理
- 账号固定：同一个任务稳定使用同一个代理
- 固定第一个：始终使用代理池第一个代理

一次注册或 AT 刷新过程中不会中途切换代理。

配置任务代理后，注册、登录、Sentinel 辅助页、Session/AT、TOTP 2FA、OAuth token 兑换和后期绑定手机号所涉及的 OpenAI/ChatGPT HTTP 请求都会使用该任务选中的代理；代理失败时不会自动回退直连。`socks5://` 输入会规范为 `socks5h://`，让域名由代理端解析。HeroSMS/SmsBower 请求也使用同一个任务代理，邮箱 API、Outlook 和 IMAP 取码仍保持独立直连。若希望同一账号跨多次操作始终固定出口，请选择“账号固定”策略。

## 手机接码

在“运行参数 → 手机接码”中选择 SmsBower 或 HeroSMS，填写 API Key、国家 ID、服务代码和可选最高单价后保存。默认国家 ID 为 `52`、服务代码为 `dr`；请以接码平台和 OpenAI 当前实际可用范围为准。

注册流程不会自动租号。如果平台在邮箱注册后停到 `add-phone`，任务会显示“待绑手机号”；此时可以在任务列表中明确勾选账号并点击“批量绑手机”，或者在单个账号的“凭据”弹窗中使用自动接码或手动填写手机号。启动自动接码前页面会提示最多可能产生的接码费用笔数；不具备后期绑号条件和已经绑定的账号会被跳过。

后期绑定会先复用账号已保存的登录态建立有效的 OpenAI 授权事务，只有服务端确实进入手机号验证步骤后才向接码平台租号。生命周期为租号、触发短信、轮询验证码、提交验证，并在成功后结算或失败时释放号码。号码复用默认关闭；任务被停止、超时或服务重启时，会根据本地恢复记录补偿取消未完成订单。API Key 只保存在服务端设置中，页面重新加载后只显示“已配置”，不会回传明文。

手动绑定会在同一个后台授权会话中依次接收手机号和验证码。发码或验码失败时会话不会立即退出，正式登录态也不会被失败结果覆盖；可以在凭据弹窗中直接换一个 `+国家码手机号` 再次发送。绑定成功后才会把更新后的登录态合并回账号文件。

## 注册与 2FA

邮箱注册取得有效 Session 后，会先确保远端账号密码已经生效，再继续开启 TOTP 2FA，页面不再提供单独的 2FA 批量入口。若组合流程在密码补设或 2FA 阶段失败，可直接对该注册任务点击“重试”。如果平台要求先绑定手机号，任务会停在“待绑手机号”，不会在注册阶段租号。

账号密码只有在远端明确接受后才标记为“已设置”。标准注册若进入 `/create-account/password`，会在邮箱 OTP 前通过 `/user/register` 设置密码；若平台直接走 passwordless 注册，则在注册完成、开启 2FA 前从 ChatGPT 官方再认证入口携带 `post_login_add_password=true`，依次进入 `/email-verification` 和 `/reset-password/new-password`，自动读取邮箱验证码并补设密码。密码和 OTP 在 trace 中会被打码；远端未接受时流程会停在 `set_password`，不会继续开启 2FA，也不会把本地生成密码显示成已生效。

已有 2FA 的账号在模拟登录时，密码前的邮箱验证仍使用该任务配置的 API URL、IMAP 或 Outlook 邮箱取码；只有密码后的明确挑战才会提交 TOTP。遇到远端验证码尝试次数上限时任务会停止并提示等待冷却，不会继续重复提交同一个验证码。

## 完整 Session

完成账号的“凭据”弹窗中可点击“获取完整 Session”。服务端会使用该账号现有登录 cookies 实时请求 ChatGPT Session，而不是读取可能过期的旧快照；结果可以复制或下载为 JSON。Session 内含 Access Token 和账号信息，属于敏感凭据，请勿发送给不可信的人。

## 测试

```bash
python -m unittest discover -s tests -v
```

测试不会实际注册 ChatGPT 账号，也不会操作真实邮箱。
