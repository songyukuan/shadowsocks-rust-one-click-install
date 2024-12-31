# Shadowsocks-Rust one click install
# Shadowsocks-Rust 一键安装脚本

这是一个用于在 Linux 系统上安装 Shadowsocks-Rust 代理服务器的自动化脚本。该脚本支持 Ubuntu、Debian、CentOS 和 Armbian 系统。使用该脚本可以快速搭建一个安全的 Shadowsocks 服务器。

## 特性

- 支持自定义密码、端口和加密方式。
- 自动安装必要的依赖项。
- 兼容主流 Linux 发行版（Ubuntu, Debian, CentOS, Armbian）。
- 提供安装过程的实时输出和错误日志。
  
## 支持的加密方式

- `aes-256-gcm`
- `aes-192-gcm`
- `aes-128-gcm`
- `aes-256-ctr`
- `aes-192-ctr`
- `aes-128-ctr`
- `aes-256-cfb`
- `aes-192-cfb`
- `aes-128-cfb`
- `chacha20-ietf-poly1305`
- `chacha20`
- `xchacha20-ietf-poly1305`
- `rc4-md5`

## 系统要求

- 支持的操作系统：Ubuntu, Debian, CentOS, Armbian。
- 必须使用 root 权限或具备 sudo 权限的用户来执行安装命令。

## 安装

1. **下载并运行安装脚本**

   在终端中运行以下命令来下载并运行脚本：

   ```bash
   curl -SL https://api.miguan.vip/download/shadowsocks/release/setup_shadowsocks-rust.sh -o setup_shadowsocks-rust.sh && sudo chmod +x ./setup_shadowsocks-rust.sh && sudo bash ./setup_shadowsocks-rust.sh
   ```

2. **安装参数**

--password <password>: 设置 Shadowsocks 服务器的密码。
--port <port>: 设置 Shadowsocks 服务器的端口，默认为随机18000-18999
--cipher <cipher>: 设置加密方式，默认为 aes-256-cfb
-y: 跳过确认步骤，自动进行安装。
例如，如果你想要设置密码为 yourpassword，端口为 12345，加密方式为 chacha20-ietf-poly1305，可以使用如下命令：

   ```bash
   sudo bash ./setup_shadowsocks-rust.sh --password yourpassword --port 12345 --cipher chacha20-ietf-poly1305 -y

   ```
## 使用
安装完成后，你的 Shadowsocks 服务器将自动启动并运行。你可以通过查看日志确认运行状态：

   ```bash
   sudo systemctl status shadowsocks-rust
   ```
你可以通过以下命令来停止或重启服务器：
   ```bash
   sudo systemctl stop shadowsocks-rust
   sudo systemctl restart shadowsocks-rust
   ```

## 卸载
如果你想卸载 Shadowsocks 服务器，只需运行以下命令：
   ```bash
   sudo bash ./setup_shadowsocks-rust.sh --uninstall
   ```
## 贡献
如果你遇到问题或有任何建议，欢迎提交 Issue 或 Pull Request。
