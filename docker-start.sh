#!/usr/bin/env bash
set -Eeuo pipefail

PROJECT_DIRECTORY="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${PROJECT_DIRECTORY}/.env"
GENERATED_INITIAL_PASSWORD=""

say() {
  printf '\n\033[1;32m[钥密 Docker]\033[0m %s\n' "$*"
}

fail() {
  printf '\n\033[1;31m[钥密 Docker] 启动失败：\033[0m%s\n' "$*" >&2
  exit 1
}

command -v docker >/dev/null 2>&1 || fail "未找到 Docker，请先安装 Docker Engine。"
docker compose version >/dev/null 2>&1 || fail "未找到 Docker Compose 插件。"
command -v openssl >/dev/null 2>&1 || fail "未找到 openssl。"
docker info >/dev/null 2>&1 || fail "当前用户无权连接 Docker 服务。"

generate_hex_secret() {
  openssl rand -hex "${1}"
}

touch_env_if_missing() {
  if [[ -f "${ENV_FILE}" ]]; then
    say "保留现有 .env 配置"
    return
  fi

  umask 077
  GENERATED_INITIAL_PASSWORD="$(generate_hex_secret 12)"
  {
    printf 'BIND_ADDRESS=127.0.0.1\n'
    printf 'HTTP_PORT=51213\n'
    printf 'SITE_ADDRESS=:80\n'
    printf 'YUEMI_INITIAL_PASSWORD=%s\n' "${GENERATED_INITIAL_PASSWORD}"
    printf 'SMTP_CONFIG_KEY=%s\n' "$(generate_hex_secret 32)"
  } >"${ENV_FILE}"
}

append_missing_secret() {
  local key="$1"
  local value="$2"
  if ! grep -q "^${key}=" "${ENV_FILE}"; then
    printf '%s=%s\n' "${key}" "${value}" >>"${ENV_FILE}"
  fi
}

touch_env_if_missing
append_missing_secret "BIND_ADDRESS" "127.0.0.1"
append_missing_secret "HTTP_PORT" "51213"
append_missing_secret "SITE_ADDRESS" ":80"
append_missing_secret "SMTP_CONFIG_KEY" "$(generate_hex_secret 32)"
if ! grep -q '^YUEMI_INITIAL_PASSWORD=' "${ENV_FILE}"; then
  GENERATED_INITIAL_PASSWORD="$(generate_hex_secret 12)"
  printf 'YUEMI_INITIAL_PASSWORD=%s\n' "${GENERATED_INITIAL_PASSWORD}" >>"${ENV_FILE}"
fi
chmod 600 "${ENV_FILE}"

say "构建并启动应用容器（仅监听 127.0.0.1:51213）"
docker compose --project-directory "${PROJECT_DIRECTORY}" \
  -f "${PROJECT_DIRECTORY}/compose.yaml" \
  up -d --build --remove-orphans app

APP_CONTAINER_ID="$(docker compose --project-directory "${PROJECT_DIRECTORY}" \
  -f "${PROJECT_DIRECTORY}/compose.yaml" ps -q app)"
[[ -n "${APP_CONTAINER_ID}" ]] || fail "应用容器未创建。"

say "等待健康检查"
for _ in $(seq 1 45); do
  STATUS="$(docker inspect --format='{{.State.Health.Status}}' "${APP_CONTAINER_ID}" 2>/dev/null || true)"
  [[ "${STATUS}" == "healthy" ]] && break
  sleep 2
done

STATUS="$(docker inspect --format='{{.State.Health.Status}}' "${APP_CONTAINER_ID}" 2>/dev/null || true)"
if [[ "${STATUS}" != "healthy" ]]; then
  docker compose --project-directory "${PROJECT_DIRECTORY}" \
    -f "${PROJECT_DIRECTORY}/compose.yaml" logs --tail=100 app
  fail "应用未通过健康检查。"
fi

HTTP_PORT="$(grep '^HTTP_PORT=' "${ENV_FILE}" | tail -n 1 | cut -d= -f2- || true)"
HTTP_PORT="${HTTP_PORT:-51213}"
say "Docker 版本已启动"
printf '%s\n' \
  "本机地址：http://127.0.0.1:${HTTP_PORT}" \
  "请让 VPS 现有 HTTPS 服务反向代理到该地址，不要把端口直接开放到公网。"
if [[ -n "${GENERATED_INITIAL_PASSWORD}" ]]; then
  printf '%s\n' \
    "首次初始主密码：${GENERATED_INITIAL_PASSWORD}" \
    "请立即保存，首次登录后必须修改。"
fi
