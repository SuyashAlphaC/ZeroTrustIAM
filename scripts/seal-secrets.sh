#!/usr/bin/env bash
set -euo pipefail
# Helper: kubeseal each key from secrets/.env.production into overlays/production/secrets-sealed.yaml.
ENV_FILE="${1:-secrets/.env.production}"
SEAL_CERT="${SEAL_CERT:?export SEAL_CERT to your kubeseal public cert PEM path}"
OUT_FILE="${OUT_FILE:-k8s/overlays/production/secrets-sealed.yaml}"

[[ -f "${ENV_FILE}" ]] || { echo "missing ${ENV_FILE}"; exit 1; }

{
  printf '%s\n' 'apiVersion: bitnami.com/v1alpha1'
  printf '%s\n' 'kind: SealedSecret'
  printf '%s\n' 'metadata:'
  printf '%s\n' '  name: ztiam-secrets'
  printf '%s\n' '  namespace: ztiam'
  printf '%s\n' 'spec:'
  printf '%s\n' '  encryptedData:'
} >"${OUT_FILE}"

while IFS= read -r line || [[ -n "${line}" ]]; do
  [[ -z "${line}" || "${line}" =~ ^# ]] && continue
  [[ "${line}" != *'='* ]] && continue
  key="${line%%=*}"
  val="${line#*=}"
  stripped="${val/#\"/}"
  stripped="${stripped/%\"/}"
  enc="$(printf '%s' "${stripped}" | kubeseal --raw --from-file="${key}=/dev/stdin" \
    --cert "${SEAL_CERT}" --namespace ztiam --name ztiam-secrets --scope cluster-wide)"
  printf '    %s: %s\n' "${key}" "${enc}" >>"${OUT_FILE}"
done <"${ENV_FILE}"

echo "wrote ${OUT_FILE}"
