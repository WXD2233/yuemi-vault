#!/usr/bin/env bash
set -Eeuo pipefail

REPOSITORY_URL="${YUEMI_REPO_URL:-https://github.com/WXD2233/yuemi-vault.git}"
REPOSITORY_REF="${YUEMI_REPO_REF:-main}"
INSTALL_DIRECTORY="${YUEMI_INSTALL_DIR:-/opt/yuemi-vault}"
DOMAIN="${1:-${YUEMI_DOMAIN:-}}"

say() {
  printf '\n\033[1;32m[钥密]\033[0m %s\n' "$*"
}

fail() {
  printf '\n\033[1;31m[钥密] 安装失败：\033[0m%s\n' "$*" >&2
  exit 1
}

if [[ "${EUID}" -ne 0 ]]; then
  fail "请使用 root 运行，例如：sudo bash install-vps.sh"
fi

if [[ ! -r /etc/os-release ]]; then
  fail "无法识别系统；当前脚本支持 Ubuntu 和 Debian。"
fi

# shellcheck disable=SC1091
. /etc/os-release
case "${ID:-}" in
  ubuntu|debian) ;;
  *) fail "当前系统 ${PRETTY_NAME:-unknown} 不受支持；请使用 Ubuntu 或 Debian。" ;;
esac

install_docker() {
  say "安装 Docker Engine 与 Compose 插件"
  apt-get update
  apt-get install -y ca-certificates curl git openssl
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL "https://download.docker.com/linux/${ID}/gpg" \
    -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc

  local suite
  if [[ "${ID}" == "ubuntu" ]]; then
    suite="${UBUNTU_CODENAME:-${VERSION_CODENAME}}"
  else
    suite="${VERSION_CODENAME}"
  fi

  cat >/etc/apt/sources.list.d/docker.sources <<EOF
Types: deb
URIs: https://download.docker.com/linux/${ID}
Suites: ${suite}
Components: stable
Architectures: $(dpkg --print-architecture)
Signed-By: /etc/apt/keyrings/docker.asc
EOF

  apt-get update
  apt-get install -y docker-ce docker-ce-cli containerd.io \
    docker-buildx-plugin docker-compose-plugin
  systemctl enable --now docker
}

if ! command -v docker >/dev/null 2>&1 || ! docker compose version >/dev/null 2>&1; then
  install_docker
else
  say "已检测到 Docker 与 Docker Compose"
  command -v git >/dev/null 2>&1 || {
    apt-get update
    apt-get install -y git
  }
  command -v openssl >/dev/null 2>&1 || {
    apt-get update
    apt-get install -y openssl
  }
fi

SCRIPT_DIRECTORY="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" 2>/dev/null && pwd || true)"
if [[ -f "${SCRIPT_DIRECTORY}/compose.yaml" && -d "${SCRIPT_DIRECTORY}/.git" ]]; then
  PROJECT_DIRECTORY="${SCRIPT_DIRECTORY}"
  say "使用当前 Git 仓库：${PROJECT_DIRECTORY}"
else
  PROJECT_DIRECTORY="${INSTALL_DIRECTORY}"
  if [[ -d "${PROJECT_DIRECTORY}/.git" ]]; then
    if ! git -C "${PROJECT_DIRECTORY}" diff-index --quiet HEAD --; then
      fail "${PROJECT_DIRECTORY} 存在未提交修改，已停止更新以避免覆盖。"
    fi
    say "更新 ${PROJECT_DIRECTORY}"
    git -C "${PROJECT_DIRECTORY}" fetch --depth 1 origin "${REPOSITORY_REF}"
    git -C "${PROJECT_DIRECTORY}" checkout -B "${REPOSITORY_REF}" FETCH_HEAD
  elif [[ -e "${PROJECT_DIRECTORY}" ]]; then
    fail "${PROJECT_DIRECTORY} 已存在但不是 Git 仓库，请更换 YUEMI_INSTALL_DIR。"
  else
    say "下载钥密到 ${PROJECT_DIRECTORY}"
    git clone --depth 1 --branch "${REPOSITORY_REF}" \
      "${REPOSITORY_URL}" "${PROJECT_DIRECTORY}"
  fi
fi

if [[ -n "${DOMAIN}" ]]; then
  if [[ "${DOMAIN}" == *"://"* || "${DOMAIN}" == *"/"* || "${DOMAIN}" == *" "* ]]; then
    fail "域名只填写主机名，例如 vault.example.com，不要带 http:// 或路径。"
  fi
  SITE_ADDRESS="${DOMAIN}"
else
  SITE_ADDRESS=":80"
fi

ENV_FILE="${PROJECT_DIRECTORY}/.env"
GENERATED_INITIAL_PASSWORD=""
generate_hex_secret() {
  openssl rand -hex "${1}"
}

if [[ -f "${ENV_FILE}" ]]; then
  say "保留现有 .env 配置"
  if ! grep -q '^SITE_ADDRESS=' "${ENV_FILE}"; then
    printf 'SITE_ADDRESS=%s\n' "${SITE_ADDRESS}" >>"${ENV_FILE}"
  fi
else
  umask 077
  printf 'SITE_ADDRESS=%s\nBIND_ADDRESS=127.0.0.1\nHTTP_PORT=51213\n' \
    "${SITE_ADDRESS}" >"${ENV_FILE}"
fi

if ! grep -q '^BIND_ADDRESS=' "${ENV_FILE}"; then
  printf 'BIND_ADDRESS=127.0.0.1\n' >>"${ENV_FILE}"
fi
if ! grep -q '^HTTP_PORT=' "${ENV_FILE}"; then
  printf 'HTTP_PORT=51213\n' >>"${ENV_FILE}"
fi
if ! grep -q '^SMTP_CONFIG_KEY=' "${ENV_FILE}"; then
  printf 'SMTP_CONFIG_KEY=%s\n' "$(generate_hex_secret 32)" >>"${ENV_FILE}"
fi
if ! grep -q '^YUEMI_INITIAL_PASSWORD=' "${ENV_FILE}"; then
  GENERATED_INITIAL_PASSWORD="$(generate_hex_secret 12)"
  printf 'YUEMI_INITIAL_PASSWORD=%s\n' "${GENERATED_INITIAL_PASSWORD}" >>"${ENV_FILE}"
fi
chmod 600 "${ENV_FILE}"

EFFECTIVE_SITE_ADDRESS="$(grep '^SITE_ADDRESS=' "${ENV_FILE}" | tail -n 1 | cut -d= -f2-)"
EFFECTIVE_HTTP_PORT="$(grep '^HTTP_PORT=' "${ENV_FILE}" | tail -n 1 | cut -d= -f2- || true)"
EFFECTIVE_HTTP_PORT="${EFFECTIVE_HTTP_PORT:-51213}"

say "构建并启动钥密"
COMPOSE_PROFILE_ARGS=()
if [[ -n "${DOMAIN}" ]]; then
  COMPOSE_PROFILE_ARGS=(--profile standalone-https)
fi
docker compose --project-directory "${PROJECT_DIRECTORY}" \
  -f "${PROJECT_DIRECTORY}/compose.yaml" "${COMPOSE_PROFILE_ARGS[@]}" \
  up -d --build --remove-orphans

APP_CONTAINER_ID="$(
  docker compose --project-directory "${PROJECT_DIRECTORY}" \
    -f "${PROJECT_DIRECTORY}/compose.yaml" ps -q app
)"
[[ -n "${APP_CONTAINER_ID}" ]] || fail "应用容器未创建。"

say "等待服务通过健康检查"
for _ in $(seq 1 30); do
  if [[ "$(docker inspect --format='{{.State.Health.Status}}' "${APP_CONTAINER_ID}" 2>/dev/null || true)" == "healthy" ]]; then
    break
  fi
  sleep 2
done

STATUS="$(docker inspect --format='{{.State.Health.Status}}' "${APP_CONTAINER_ID}" 2>/dev/null || true)"
if [[ "${STATUS}" != "healthy" ]]; then
  docker compose --project-directory "${PROJECT_DIRECTORY}" logs --tail=80 app
  fail "应用未能通过健康检查，请查看上面的日志。"
fi

if [[ "${EFFECTIVE_SITE_ADDRESS}" == :* ]]; then
  ACCESS_URL="http://127.0.0.1:${EFFECTIVE_HTTP_PORT}"
  FIREWALL_HINT="服务默认只监听本机。请让现有 HTTPS 反向代理转发到 127.0.0.1:${EFFECTIVE_HTTP_PORT}，不要把该端口直接暴露到公网。"
elif [[ "${EFFECTIVE_SITE_ADDRESS}" == http://* || "${EFFECTIVE_SITE_ADDRESS}" == https://* ]]; then
  ACCESS_URL="${EFFECTIVE_SITE_ADDRESS}"
  FIREWALL_HINT="域名模式需要确保 HTTPS 入口可访问；如已有反向代理，请将域名转发到 127.0.0.1:${EFFECTIVE_HTTP_PORT}。"
else
  ACCESS_URL="https://${EFFECTIVE_SITE_ADDRESS}"
  FIREWALL_HINT="自动 HTTPS 模式需要在 VPS 防火墙/安全组放行 TCP/UDP 443。"
fi

say "安装完成"
printf '%s\n' \
  "访问地址：${ACCESS_URL}" \
  "首次登录后必须立即修改主密码。" \
  "数据保存在 Docker 卷 yuemi-vault_vault_data 中。" \
  "${FIREWALL_HINT}"
if [[ -n "${GENERATED_INITIAL_PASSWORD}" ]]; then
  printf '%s\n' \
    "首次初始主密码：${GENERATED_INITIAL_PASSWORD}" \
    "该密码只在本次安装时显示，请立即保存并在首次登录后修改。"
fi
