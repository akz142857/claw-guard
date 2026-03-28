# macOS 签名、公证与发布指南

## 前提条件

- Apple Developer Program 账号（$99/年）
- **Developer ID Application** 证书（已安装到钥匙串）
- App-Specific Password（在 appleid.apple.com → 登录安全 → App 专用密码 生成）

### 验证证书已安装

```bash
security find-identity -v -p codesigning | grep "Developer ID Application"
```

应输出类似：
```
"Developer ID Application: Clay & Cosmos (Tianjin) Technology Co., Ltd. (V49J3X8K3S)"
```

## 快速开始

### 一键构建（仅本地测试，不签名）

```bash
./scripts/bundle-macos.sh
```

产物：`target/aarch64-apple-darwin/release/Claw Guard.app`

### 完整发布（签名 + 公证 + DMG）

```bash
export DEVELOPER_ID="Developer ID Application: Clay & Cosmos (Tianjin) Technology Co., Ltd. (V49J3X8K3S)"
export APPLE_ID="developer@taoyuzhijian.com"
export APPLE_TEAM_ID="V49J3X8K3S"
export APPLE_APP_PASSWORD="xxxx-xxxx-xxxx-xxxx"

# 如果在中国大陆，建议设置代理加速公证
export https_proxy=http://127.0.0.1:7890 http_proxy=http://127.0.0.1:7890 all_proxy=http://127.0.0.1:7890

./scripts/bundle-macos.sh --sign --notarize --dmg
```

### 构建 Intel (x86_64) 版本

```bash
./scripts/bundle-macos.sh --sign --notarize --dmg --target x86_64-apple-darwin
```

## 分步手动操作

如果自动脚本中途失败（如公证网络超时），可以手动完成剩余步骤。

### 1. 构建

```bash
cargo build --release --target aarch64-apple-darwin
```

### 2. 创建 .app Bundle

```bash
VERSION=$(grep '^version' Cargo.toml | head -1 | sed 's/.*"\(.*\)".*/\1/')
APP_DIR="target/aarch64-apple-darwin/release/Claw Guard.app"

mkdir -p "$APP_DIR/Contents/MacOS"
mkdir -p "$APP_DIR/Contents/Resources"
cp target/aarch64-apple-darwin/release/claw-guard "$APP_DIR/Contents/MacOS/"
chmod +x "$APP_DIR/Contents/MacOS/claw-guard"
sed "s/__VERSION__/${VERSION}/g" macos/Info.plist > "$APP_DIR/Contents/Info.plist"
cp assets/icon.icns "$APP_DIR/Contents/Resources/"
```

### 3. 签名

```bash
codesign --force --deep --options runtime \
  --sign "$DEVELOPER_ID" \
  --entitlements macos/entitlements.plist \
  --timestamp \
  "$APP_DIR"

# 验证
codesign --verify --deep --strict "$APP_DIR"
```

### 4. 公证

```bash
# 打包提交
ditto -c -k --keepParent "$APP_DIR" notarize.zip

# 提交（--wait 会阻塞等待结果，通常 5-15 分钟）
xcrun notarytool submit notarize.zip \
  --apple-id "$APPLE_ID" \
  --team-id "$APPLE_TEAM_ID" \
  --password "$APPLE_APP_PASSWORD" \
  --wait

rm notarize.zip
```

如果 `--wait` 因网络超时中断，可以手动查询状态：

```bash
# 查看所有提交记录
xcrun notarytool history \
  --apple-id "$APPLE_ID" \
  --team-id "$APPLE_TEAM_ID" \
  --password "$APPLE_APP_PASSWORD"

# 查看指定提交的状态
xcrun notarytool info <SUBMISSION_ID> \
  --apple-id "$APPLE_ID" \
  --team-id "$APPLE_TEAM_ID" \
  --password "$APPLE_APP_PASSWORD"

# 查看失败原因（状态为 Invalid 时）
xcrun notarytool log <SUBMISSION_ID> \
  --apple-id "$APPLE_ID" \
  --team-id "$APPLE_TEAM_ID" \
  --password "$APPLE_APP_PASSWORD"
```

### 5. 装订票据

公证状态变为 **Accepted** 后：

```bash
xcrun stapler staple "$APP_DIR"
```

### 6. 打包 DMG

```bash
DMG_STAGING=$(mktemp -d)
cp -R "$APP_DIR" "$DMG_STAGING/"
ln -s /Applications "$DMG_STAGING/Applications"
hdiutil create -volname "Claw Guard" \
  -srcfolder "$DMG_STAGING" \
  -ov -format UDZO \
  "ClawGuard-v${VERSION}-darwin-arm64.dmg"
rm -rf "$DMG_STAGING"

# 签名 DMG
codesign --force --sign "$DEVELOPER_ID" --timestamp "ClawGuard-v${VERSION}-darwin-arm64.dmg"

# （可选）公证 DMG — 非必须，.app 本身已公证即可
xcrun notarytool submit "ClawGuard-v${VERSION}-darwin-arm64.dmg" \
  --apple-id "$APPLE_ID" \
  --team-id "$APPLE_TEAM_ID" \
  --password "$APPLE_APP_PASSWORD" \
  --wait
xcrun stapler staple "ClawGuard-v${VERSION}-darwin-arm64.dmg"
```

## 验证最终产物

```bash
# 验证 .app 签名和公证
spctl --assess --type execute --verbose "Claw Guard.app"
# 期望输出: accepted, source=Notarized Developer ID

# 验证票据
stapler validate "Claw Guard.app"
# 期望输出: The validate action worked!
```

## CI/CD 自动化

GitHub Actions 已配置自动签名和公证（`.github/workflows/release.yml`）。

需要在 GitHub repo → Settings → Secrets and variables → Actions 中添加：

| Secret | 值 | 说明 |
|--------|-----|------|
| `MACOS_CERTIFICATE` | base64 编码的 .p12 文件 | `base64 -i cert.p12 \| pbcopy` |
| `MACOS_CERTIFICATE_PASSWORD` | .p12 导出密码 | 钥匙串导出时设置的密码 |
| `DEVELOPER_ID` | `Developer ID Application: Clay & Cosmos (Tianjin) Technology Co., Ltd. (V49J3X8K3S)` | 签名身份 |
| `APPLE_ID` | `developer@taoyuzhijian.com` | Apple ID 邮箱 |
| `APPLE_TEAM_ID` | `V49J3X8K3S` | Team ID |
| `APPLE_APP_PASSWORD` | App 专用密码 | appleid.apple.com 生成 |

### 导出 .p12 证书（供 CI 使用）

1. 打开 **钥匙串访问**
2. 找到 `Developer ID Application: Clay & Cosmos ...` 证书
3. 展开证书，同时选中证书和私钥
4. 右键 → 导出 2 项... → 保存为 `.p12`，设置密码
5. 编码：`base64 -i certificate.p12 | pbcopy`
6. 粘贴到 GitHub Secret `MACOS_CERTIFICATE`

## 文件说明

| 文件 | 用途 |
|------|------|
| `macos/Info.plist` | App 元数据模板，`__VERSION__` 会被自动替换 |
| `macos/entitlements.plist` | Hardened Runtime 权限（网络访问、文件读取） |
| `scripts/bundle-macos.sh` | 自动化打包脚本 |
| `assets/icon.png` | 源图标（256x256） |
| `assets/icon.icns` | 自动生成的 macOS 图标 |

## 常见问题

**Q: 公证提交后一直 In Progress？**
A: Apple 公证通常 5-15 分钟，从中国大陆提交可能更慢。设置代理可加速轮询。文件上传成功后即使轮询断开，Apple 仍会继续处理。

**Q: 公证返回 Invalid？**
A: 运行 `xcrun notarytool log <ID> ...` 查看具体原因。常见原因：未启用 Hardened Runtime、使用了被禁止的 API、二进制未签名。

**Q: 图标模糊？**
A: 当前源图标是 256x256，建议提供 1024x1024 的 `icon.png` 以获得最佳显示效果。

**Q: DMG 公证是否必须？**
A: 不是必须的。macOS Gatekeeper 检查的是 `.app` 本身的公证状态，只要 `.app` 已公证并装订票据，用户从 DMG 安装后即可正常使用。
