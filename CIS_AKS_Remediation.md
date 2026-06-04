# CIS AKS Remediation Manual

## Purpose

This document describes a host-level remediation DaemonSet for Kubernetes worker nodes.

The script has been prepared for:

- AKS nodes running Azure Linux.
- Ubuntu-based Kubernetes worker nodes.

It has been tested on Ubuntu. It is also designed to work on Azure Linux by using Azure Linux-compatible paths and package manager configuration files.

> Important: This remediation changes host OS files on every matching Linux node. Test in a lab or a small node pool before broad rollout.

## Usage model

This manual is designed for the following workflow:

1. Log in to the target environment.
2. Confirm `kubectl` is working and points to the correct cluster.
3. Paste the one-shot script from this document.
4. The script automatically creates the remediation ConfigMap and DaemonSet.

## Intentionally skipped setting

The following item is intentionally not remediated:

| CIS ID | Control | Status |
|---|---|---|
| 5.1.1 | Ensure cron daemon is enabled | Skipped intentionally |

Reason: enabling or installing `crond` was removed from the remediation by request.

The script still fixes cron file and directory permissions, but it does not install, unmask, start, or enable the cron daemon.

## Settings fixed by this remediation

| CIS ID | Control | Remediation applied |
|---|---|---|
| 1.1.2.1.1 | Ensure `/tmp` is a separate partition | Adds `/tmp` `tmpfs` entry to `/etc/fstab`, unmasks `tmp.mount`, mounts/remounts `/tmp` as `tmpfs` |
| 1.1.2.1.2 | Ensure `nodev` option set on `/tmp` partition | Adds/remounts `/tmp` with `nodev` |
| 1.1.2.1.3 | Ensure `nosuid` option set on `/tmp` partition | Adds/remounts `/tmp` with `nosuid` |
| Extra hardening | `/tmp` `noexec` | Adds/remounts `/tmp` with `noexec` |
| 1.2.1.2 | Ensure `gpgcheck` is configured | Sets `gpgcheck=1` in `/etc/dnf/dnf.conf` and normalizes `gpgcheck=1` in `/etc/yum.repos.d/*.repo` |
| 1.2.1.3 | Ensure TDNF `gpgcheck` is globally activated | Sets `gpgcheck=1` in `/etc/tdnf/tdnf.conf` |
| 1.3.3 | Ensure core dump backtraces are disabled | Sets `ProcessSizeMax=0` in systemd coredump config |
| 1.3.4 | Ensure core dump storage is disabled | Sets `Storage=none` in systemd coredump config |
| 5.1.2 | Ensure permissions on `/etc/crontab` are configured | If present, sets owner `root:root` and mode `0600` |
| 5.1.3 | Ensure permissions on `/etc/cron.hourly` are configured | Creates if missing, sets owner `root:root` and mode `0700` |
| 5.1.4 | Ensure permissions on `/etc/cron.daily` are configured | Creates if missing, sets owner `root:root` and mode `0700` |
| 5.1.5 | Ensure permissions on `/etc/cron.weekly` are configured | Creates if missing, sets owner `root:root` and mode `0700` |
| 5.1.6 | Ensure permissions on `/etc/cron.monthly` are configured | Creates if missing, sets owner `root:root` and mode `0700` |
| 5.1.7 | Ensure permissions on `/etc/cron.d` are configured | Creates if missing, sets owner `root:root` and mode `0700` |
| 5.2.1 | Ensure access to `/etc/ssh/sshd_config` is configured | Sets `/etc/ssh/sshd_config` and `/etc/ssh/sshd_config.d/*.conf` owner `root:root`, mode `0600` |
| 5.4.1 | Ensure password creation requirements are configured | Sets `/etc/security/pwquality.conf`; ensures `pam_pwquality.so retry=3` in `/etc/pam.d/system-auth` and `/etc/pam.d/system-password` |
| 5.4.2 | Ensure lockout for failed password attempts is configured | Adds ordered `pam_faillock.so` auth/account lines to `/etc/pam.d/system-auth` and `/etc/pam.d/system-password` |
| 5.4.3 | Ensure password hashing algorithm is SHA-512 | Ensures `pam_unix.so sha512`; sets `ENCRYPT_METHOD SHA512` in `/etc/login.defs` |
| 5.4.4 | Ensure password reuse is limited | Adds `pam_pwhistory.so use_authtok remember=5 retry=3` after `pam_pwquality.so` |
| 6.1.3.1 | Ensure access to all logfiles has been configured | Restricts `/var/log` file and directory permissions; normalizes regular log-file ownership to `root:root` |
| 7.1.5 | Ensure access to `/etc/shadow` is configured | Sets owner `root:root`, mode `0000` |
| 7.1.6 | Ensure access to `/etc/shadow-` is configured | Sets owner `root:root`, mode `0000` |
| 7.1.7 | Ensure access to `/etc/gshadow` is configured | Sets owner `root:root`, mode `0000` |
| 7.1.8 | Ensure access to `/etc/gshadow-` is configured | Sets owner `root:root`, mode `0000` |

## One-shot remediation script

Paste the following script after logging in to the environment and confirming that `kubectl` works.

```bash
#!/usr/bin/env bash
set -euo pipefail

NAMESPACE="kube-system"
APP_NAME="cis-aks-remediation"
SCRIPT_CM="cis-aks-remediation-script"
LOCAL_SCRIPT="/tmp/cis-aks-remediate.sh"
LOCAL_DS="/tmp/cis-aks-remediation-ds.yaml"

echo "[INFO] Creating CIS AKS remediation script at ${LOCAL_SCRIPT}"

cat > "${LOCAL_SCRIPT}" <<'SCRIPT'
#!/bin/sh
set -eu

log() {
  echo "[cis-aks-remediation] $*"
}

host_exec() {
  cmd="$1"

  if command -v nsenter >/dev/null 2>&1; then
    nsenter -t 1 -m -u -i -n -p -- /bin/sh -c "$cmd"
  elif [ -x /host/usr/bin/nsenter ]; then
    chroot /host /usr/bin/nsenter -t 1 -m -u -i -n -p -- /bin/sh -c "$cmd"
  else
    chroot /host /bin/sh -c "$cmd"
  fi
}

backup_once() {
  file="$1"
  if [ -f "$file" ] && [ ! -f "${file}.cis-aks-remediation.bak" ]; then
    cp -p "$file" "${file}.cis-aks-remediation.bak" || true
  fi
}

ensure_ini_setting() {
  file="$1"
  section="$2"
  key="$3"
  value="$4"

  mkdir -p "$(dirname "$file")"
  touch "$file"
  backup_once "$file"

  if grep -qE "^[[:space:]]*${key}[[:space:]]*=" "$file"; then
    sed -i "s|^[[:space:]]*${key}[[:space:]]*=.*|${key}=${value}|g" "$file"
    return
  fi

  if grep -qE "^[[:space:]]*\[${section}\]" "$file"; then
    sed -i "/^[[:space:]]*\[${section}\]/a ${key}=${value}" "$file"
    return
  fi

  {
    echo ""
    echo "[${section}]"
    echo "${key}=${value}"
  } >> "$file"
}

ensure_login_defs() {
  key="$1"
  value="$2"
  file="/host/etc/login.defs"

  mkdir -p /host/etc
  touch "$file"
  backup_once "$file"

  if grep -qE "^[[:space:]]*${key}[[:space:]]+" "$file"; then
    sed -i "s|^[[:space:]]*${key}[[:space:]].*|${key} ${value}|g" "$file"
  else
    echo "${key} ${value}" >> "$file"
  fi
}

fix_tmp_mount() {
  log "Fixing /tmp mount: separate tmpfs with nodev,nosuid,noexec"

  mkdir -p /host/tmp
  chmod 1777 /host/tmp

  mkdir -p /host/etc
  touch /host/etc/fstab
  backup_once /host/etc/fstab

  tmp_fstab="/host/etc/fstab.cis-tmp"

  awk '
    BEGIN { found=0 }
    /^[[:space:]]*#/ { print; next }
    NF >= 3 && $2 == "/tmp" {
      found=1
      if ($3 == "tmpfs") {
        print "tmpfs /tmp tmpfs defaults,rw,nosuid,nodev,noexec,relatime,size=2G,mode=1777 0 0"
      } else {
        print $1 " /tmp " $3 " defaults,rw,nosuid,nodev,noexec,relatime 0 0"
      }
      next
    }
    { print }
    END {
      if (found == 0) {
        print "tmpfs /tmp tmpfs defaults,rw,nosuid,nodev,noexec,relatime,size=2G,mode=1777 0 0"
      }
    }
  ' /host/etc/fstab > "$tmp_fstab"

  cat "$tmp_fstab" > /host/etc/fstab
  rm -f "$tmp_fstab"

  host_exec "systemctl unmask tmp.mount >/dev/null 2>&1 || true"
  host_exec "systemctl daemon-reload >/dev/null 2>&1 || true"
  host_exec "mount /tmp >/dev/null 2>&1 || mount -t tmpfs -o defaults,rw,nosuid,nodev,noexec,relatime,size=2G,mode=1777 tmpfs /tmp >/dev/null 2>&1 || true"
  host_exec "mount -o remount,rw,nosuid,nodev,noexec,relatime,mode=1777 /tmp >/dev/null 2>&1 || true"
}

fix_gpgcheck() {
  log "Fixing DNF and TDNF gpgcheck"

  mkdir -p /host/etc/dnf
  ensure_ini_setting /host/etc/dnf/dnf.conf main gpgcheck 1

  if [ -d /host/etc/yum.repos.d ]; then
    find /host/etc/yum.repos.d -type f -name "*.repo" | while read -r repo; do
      backup_once "$repo"
      sed -i 's/^[[:space:]]*gpgcheck[[:space:]]*=.*/gpgcheck=1/g' "$repo"
    done
  fi

  mkdir -p /host/etc/tdnf
  ensure_ini_setting /host/etc/tdnf/tdnf.conf main gpgcheck 1
}

fix_coredump() {
  log "Fixing systemd coredump settings"

  mkdir -p /host/etc/systemd /host/etc/systemd/coredump.conf.d

  ensure_ini_setting /host/etc/systemd/coredump.conf Coredump Storage none
  ensure_ini_setting /host/etc/systemd/coredump.conf Coredump ProcessSizeMax 0

  cat > /host/etc/systemd/coredump.conf.d/60-cis-coredump.conf <<'EOF'
[Coredump]
Storage=none
ProcessSizeMax=0
EOF

  chmod 0644 /host/etc/systemd/coredump.conf
  chmod 0644 /host/etc/systemd/coredump.conf.d/60-cis-coredump.conf
}

fix_cron_permissions_only() {
  log "Fixing cron permissions only; cron daemon enablement is intentionally skipped"

  if [ -f /host/etc/crontab ]; then
    chown 0:0 /host/etc/crontab
    chmod 0600 /host/etc/crontab
  fi

  for dir in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d; do
    mkdir -p "/host${dir}"
    chown 0:0 "/host${dir}"
    chmod 0700 "/host${dir}"
  done
}

fix_sshd_config_permissions() {
  log "Fixing SSH server config permissions"

  if [ -f /host/etc/ssh/sshd_config ]; then
    chown 0:0 /host/etc/ssh/sshd_config
    chmod 0600 /host/etc/ssh/sshd_config
  fi

  if [ -d /host/etc/ssh/sshd_config.d ]; then
    find /host/etc/ssh/sshd_config.d -type f -name "*.conf" | while read -r sshconf; do
      chown 0:0 "$sshconf"
      chmod 0600 "$sshconf"
    done
  fi
}

fix_pwquality_conf() {
  log "Fixing password quality configuration"

  mkdir -p /host/etc/security
  touch /host/etc/security/pwquality.conf
  backup_once /host/etc/security/pwquality.conf

  cat > /host/etc/security/pwquality.conf <<'EOF'
minlen = 14
minclass = 4
dcredit = -1
ucredit = -1
ocredit = -1
lcredit = -1
EOF

  chmod 0644 /host/etc/security/pwquality.conf
}

fix_login_defs_sha512() {
  log "Fixing ENCRYPT_METHOD SHA512 in /etc/login.defs"
  ensure_login_defs ENCRYPT_METHOD SHA512
}

fix_pam_file() {
  pamfile="$1"

  log "Fixing PAM file: $pamfile"

  mkdir -p "$(dirname "$pamfile")"

  if [ ! -f "$pamfile" ]; then
    log "$pamfile does not exist; creating minimal CIS-aligned file"
    cat > "$pamfile" <<'EOF'
auth required pam_env.so
auth required pam_faillock.so preauth silent audit deny=5 unlock_time=900
auth sufficient pam_unix.so nullok try_first_pass
auth [default=die] pam_faillock.so authfail audit deny=5 unlock_time=900
auth requisite pam_succeed_if.so uid >= 1000 quiet_success
auth required pam_deny.so
account required pam_faillock.so
account required pam_unix.so
password requisite pam_pwquality.so retry=3
password requisite pam_pwhistory.so use_authtok remember=5 retry=3
password sufficient pam_unix.so sha512 shadow try_first_pass use_authtok
password required pam_deny.so
EOF
    chmod 0644 "$pamfile"
    return
  fi

  backup_once "$pamfile"

  sed -i '/pam_faillock\.so/d' "$pamfile"
  sed -i '/pam_pwhistory\.so/d' "$pamfile"

  if grep -qE '^[[:space:]]*password[[:space:]].*pam_pwquality\.so' "$pamfile"; then
    sed -i -E '/^[[:space:]]*password[[:space:]].*pam_pwquality\.so/ {
      s/[[:space:]]retry=[0-9]+//g
      s/[[:space:]]*$/ retry=3/
    }' "$pamfile"
  else
    if grep -qE '^[[:space:]]*password[[:space:]].*pam_unix\.so' "$pamfile"; then
      sed -i '/^[[:space:]]*password[[:space:]].*pam_unix\.so/i password requisite pam_pwquality.so retry=3' "$pamfile"
    else
      echo 'password requisite pam_pwquality.so retry=3' >> "$pamfile"
    fi
  fi

  if grep -qE '^[[:space:]]*password[[:space:]].*pam_unix\.so' "$pamfile"; then
    sed -i -E '/^[[:space:]]*password[[:space:]].*pam_unix\.so/ {
      s/[[:space:]]md5\b//g
      s/[[:space:]]yescrypt\b//g
      s/[[:space:]]bigcrypt\b//g
      s/[[:space:]]blowfish\b//g
      /[[:space:]]sha512\b/! s/$/ sha512/
    }' "$pamfile"
  else
    echo 'password sufficient pam_unix.so sha512 shadow try_first_pass use_authtok' >> "$pamfile"
  fi

  awk '
    {
      print
      if (!done && $1 == "password" && $0 ~ /pam_pwquality\.so/) {
        print "password requisite pam_pwhistory.so use_authtok remember=5 retry=3"
        done=1
      }
    }
    END {
      if (!done) {
        print "password requisite pam_pwhistory.so use_authtok remember=5 retry=3"
      }
    }
  ' "$pamfile" > "${pamfile}.tmp"
  cat "${pamfile}.tmp" > "$pamfile"
  rm -f "${pamfile}.tmp"

  awk '
    BEGIN {
      preauth_done=0
      authfail_done=0
      account_done=0
    }

    {
      if (!preauth_done && $1 == "auth" && $0 ~ /pam_env\.so/) {
        print
        print "auth required pam_faillock.so preauth silent audit deny=5 unlock_time=900"
        preauth_done=1
        next
      }

      if (!preauth_done && $1 == "auth" && $0 !~ /pam_env\.so/) {
        print "auth required pam_faillock.so preauth silent audit deny=5 unlock_time=900"
        preauth_done=1
      }

      if (!authfail_done && $1 == "auth" && ($0 ~ /pam_succeed_if\.so/ || $0 ~ /pam_deny\.so/)) {
        print "auth [default=die] pam_faillock.so authfail audit deny=5 unlock_time=900"
        authfail_done=1
      }

      if (!account_done && $1 == "account") {
        print "account required pam_faillock.so"
        account_done=1
      }

      print
    }

    END {
      if (!preauth_done) {
        print "auth required pam_faillock.so preauth silent audit deny=5 unlock_time=900"
      }
      if (!authfail_done) {
        print "auth [default=die] pam_faillock.so authfail audit deny=5 unlock_time=900"
      }
      if (!account_done) {
        print "account required pam_faillock.so"
      }
    }
  ' "$pamfile" > "${pamfile}.tmp"
  cat "${pamfile}.tmp" > "$pamfile"
  rm -f "${pamfile}.tmp"

  chmod 0644 "$pamfile"
}

fix_pam() {
  log "Fixing PAM password policy"

  mkdir -p /host/etc/pam.d

  if [ -f /host/etc/pam.d/system-auth ] || [ -f /host/etc/pam.d/system-password ]; then
    fix_pam_file /host/etc/pam.d/system-auth
    fix_pam_file /host/etc/pam.d/system-password
  fi

  if [ -f /host/etc/pam.d/common-password ]; then
    backup_once /host/etc/pam.d/common-password
    if grep -qE 'pam_pwquality\.so' /host/etc/pam.d/common-password; then
      sed -i -E '/pam_pwquality\.so/ {
        s/[[:space:]]retry=[0-9]+//g
        s/[[:space:]]*$/ retry=3/
      }' /host/etc/pam.d/common-password
    fi
    if grep -qE 'pam_unix\.so' /host/etc/pam.d/common-password; then
      sed -i -E '/pam_unix\.so/ {
        s/[[:space:]]yescrypt\b//g
        s/[[:space:]]md5\b//g
        /[[:space:]]sha512\b/! s/$/ sha512/
      }' /host/etc/pam.d/common-password
    fi
  fi
}

fix_logfiles() {
  log "Fixing logfile permissions"

  if [ -d /host/var/log ]; then
    find /host/var/log -type f -exec chmod u-x,g-wx,o-rwx {} + 2>/dev/null || true
    find /host/var/log -type d -exec chmod g-w,o-rwx {} + 2>/dev/null || true
    find /host/var/log -type f -exec chown 0:0 {} + 2>/dev/null || true
  fi
}

fix_shadow_gshadow() {
  log "Fixing shadow and gshadow permissions"

  for file in /etc/shadow /etc/shadow- /etc/gshadow /etc/gshadow-; do
    host_file="/host${file}"
    if [ -e "$host_file" ]; then
      chown 0:0 "$host_file"
      chmod 0000 "$host_file"
    fi
  done
}

main() {
  fix_tmp_mount
  fix_gpgcheck
  fix_coredump
  fix_cron_permissions_only
  fix_sshd_config_permissions
  fix_pwquality_conf
  fix_login_defs_sha512
  fix_pam
  fix_logfiles
  fix_shadow_gshadow

  log "Done. Keeping pod alive so the remediation is reapplied on replacement nodes."
  sleep infinity
}

main
SCRIPT

chmod +x "${LOCAL_SCRIPT}"

echo "[INFO] Recreating ConfigMap ${SCRIPT_CM}"
kubectl -n "${NAMESPACE}" delete configmap "${SCRIPT_CM}" --ignore-not-found
kubectl -n "${NAMESPACE}" create configmap "${SCRIPT_CM}" \
  --from-file=remediate.sh="${LOCAL_SCRIPT}"

echo "[INFO] Creating DaemonSet manifest at ${LOCAL_DS}"

cat > "${LOCAL_DS}" <<'YAML'
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: cis-aks-remediation
  namespace: kube-system
  labels:
    app: cis-aks-remediation
spec:
  selector:
    matchLabels:
      app: cis-aks-remediation
  template:
    metadata:
      labels:
        app: cis-aks-remediation
    spec:
      hostPID: true
      hostIPC: true
      hostNetwork: true
      nodeSelector:
        kubernetes.io/os: linux
      tolerations:
      - operator: Exists
      containers:
      - name: remediate
        image: mcr.microsoft.com/azurelinux/base/core:3.0
        imagePullPolicy: IfNotPresent
        securityContext:
          privileged: true
          runAsUser: 0
        command:
        - /bin/sh
        - /scripts/remediate.sh
        volumeMounts:
        - name: host
          mountPath: /host
          mountPropagation: Bidirectional
        - name: script
          mountPath: /scripts
      volumes:
      - name: host
        hostPath:
          path: /
          type: Directory
      - name: script
        configMap:
          name: cis-aks-remediation-script
          defaultMode: 0755
YAML

echo "[INFO] Recreating DaemonSet ${APP_NAME}"
kubectl -n "${NAMESPACE}" delete daemonset "${APP_NAME}" --ignore-not-found
kubectl apply -f "${LOCAL_DS}"

echo "[INFO] Waiting for DaemonSet rollout"
kubectl -n "${NAMESPACE}" rollout status daemonset/"${APP_NAME}"

echo "[INFO] Remediation DaemonSet deployed"
kubectl -n "${NAMESPACE}" get pods -l app="${APP_NAME}" -o wide

```

## What the script creates

The script creates:

```text
ConfigMap: kube-system/cis-aks-remediation-script
DaemonSet: kube-system/cis-aks-remediation
```

The DaemonSet runs one privileged pod on each Linux node.

## Backups

Before changing existing files, the remediation script creates one-time backups with this suffix:

```text
.cis-aks-remediation.bak
```

Examples:

```text
/etc/fstab.cis-aks-remediation.bak
/etc/dnf/dnf.conf.cis-aks-remediation.bak
/etc/tdnf/tdnf.conf.cis-aks-remediation.bak
/etc/systemd/coredump.conf.cis-aks-remediation.bak
/etc/security/pwquality.conf.cis-aks-remediation.bak
/etc/login.defs.cis-aks-remediation.bak
/etc/pam.d/system-auth.cis-aks-remediation.bak
/etc/pam.d/system-password.cis-aks-remediation.bak
```

## Remove Kubernetes remediation objects

This removes the Kubernetes objects only. It does not automatically revert host OS changes.

```bash
kubectl -n kube-system delete ds cis-aks-remediation
kubectl -n kube-system delete cm cis-aks-remediation-script
```

## Rollback notes

Rollback should be performed carefully on one test node first.

Example rollback for one file:

```bash
cp -p /etc/pam.d/system-auth.cis-aks-remediation.bak /etc/pam.d/system-auth
```

For `/tmp`, restore or edit the `/tmp` line in `/etc/fstab`, then remount or reboot the node during a maintenance window.

## Operational notes

### Privileged DaemonSet

This remediation requires a privileged DaemonSet because it modifies host OS files and remounts `/tmp`.

### `/tmp` behavior

The remediation configures:

```text
tmpfs /tmp tmpfs defaults,rw,nosuid,nodev,noexec,relatime,size=2G,mode=1777 0 0
```

Files previously under `/tmp` can be hidden while the tmpfs mount is active. Files stored in `/tmp` will not persist after reboot.

### PAM behavior

The remediation modifies PAM files. This can affect local authentication behavior. Validate before broad rollout.

### Persistence

The DaemonSet remains running so that remediation is applied again on new or replaced nodes, including scale-out or node image upgrade events.
