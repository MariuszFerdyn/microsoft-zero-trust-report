# Deploy PostgreSQL with Crunchy Data PGO Operator on Kubernetes

No repo clone or local downloads required. Apply everything from GitHub over remote kustomize, then create the cluster with an inline heredoc. Assumes you are already logged in to `kubectl`.

> **Note:** The `postgres-operator-examples` repo no longer ships an operator installer (it only contains example clusters). The operator install now lives in the main `postgres-operator` repo under `config/`. The commands below are verified against tag **v5.8.8**.

## 1. Install the operator (no clone)

Use the `//` separator between repo and in-repo path, and pin a release tag with `?ref=`. Quote the URLs so the shell doesn't choke on `?`.

```bash
KUSTOMIZE_GIT_TIMEOUT=120s kubectl apply --server-side -k "https://github.com/CrunchyData/postgres-operator//config/namespace?ref=v5.8.8"
KUSTOMIZE_GIT_TIMEOUT=120s kubectl apply --server-side -k "https://github.com/CrunchyData/postgres-operator//config/default?ref=v5.8.8"
```

> `KUSTOMIZE_GIT_TIMEOUT=120s` is set because remote kustomize has to `git fetch` the repo first; the default timeout can be too short to clone it over a slow connection (network, not a path issue). If it still times out, retry on a faster connection.

### Wait for the operator to be ready

```bash
kubectl -n postgres-operator wait --for=condition=Ready pod \
  --selector=postgres-operator.crunchydata.com/control-plane=postgres-operator --timeout=120s
```

## 2. Create the cluster (inline)

```bash
kubectl apply -f - <<'EOF'
apiVersion: postgres-operator.crunchydata.com/v1beta1
kind: PostgresCluster
metadata:
  name: hippo
  namespace: postgres-operator
spec:
  postgresVersion: 16
  instances:
    - name: instance1
      replicas: 2
      dataVolumeClaimSpec:
        accessModes: ["ReadWriteOnce"]
        resources:
          requests:
            storage: 10Gi
  backups:
    pgbackrest:
      repos:
        - name: repo1
          volume:
            volumeClaimSpec:
              accessModes: ["ReadWriteOnce"]
              resources:
                requests:
                  storage: 10Gi
EOF
```

Watch it come up:

```bash
kubectl -n postgres-operator get pods --selector=postgres-operator.crunchydata.com/cluster=hippo -w
```

## 3. Log in

First make sure a Postgres client is installed locally (`psql`):

```bash
sudo apt update && sudo apt install -y postgresql-client
```

Forward a local port to the primary and connect. Using local port **5433** avoids clashing with a local Postgres already on 5432:

```bash
PG_PRIMARY=$(kubectl -n postgres-operator get pod -o name \
  -l postgres-operator.crunchydata.com/cluster=hippo,postgres-operator.crunchydata.com/role=master)
kubectl -n postgres-operator port-forward "${PG_PRIMARY}" 5433:5432 &

PGPASSWORD=$(kubectl -n postgres-operator get secret hippo-pguser-hippo -o go-template='{{.data.password | base64decode}}') \
psql -h localhost -p 5433 -U hippo -d hippo
```

That drops you into the database prompt.

### Reconnecting (one self-contained command)

To reconnect later without leaving stale forwards behind, run this single command — it opens the port-forward, connects, and automatically kills the forward the moment you quit `psql` (`\q`):

```bash
PG_PRIMARY=$(kubectl -n postgres-operator get pod -o name -l postgres-operator.crunchydata.com/cluster=hippo,postgres-operator.crunchydata.com/role=master); \
kubectl -n postgres-operator port-forward "${PG_PRIMARY}" 5433:5432 >/dev/null 2>&1 & PF_PID=$!; sleep 2; \
PGPASSWORD=$(kubectl -n postgres-operator get secret hippo-pguser-hippo -o go-template='{{.data.password | base64decode}}') \
psql -h localhost -p 5433 -U hippo -d hippo; \
kill $PF_PID
```

`PF_PID=$!` captures the forward's process id, and the trailing `kill $PF_PID` runs as soon as `psql` exits — so the forward dies with your session and port 5433 is freed for next time.

### Troubleshooting

- **`You must install at least one postgresql-client-<version> package`** — `psql` isn't installed. Run the `apt install postgresql-client` step above.
- **`bind: address already in use` on 5432** — a previous `port-forward` is still running, or local Postgres owns the port. Use a different local port (e.g. `5433:5432` as above), or clean up stale forwards: `pkill -f "port-forward.*5432"`. Use `jobs` / `kill %1` to inspect and kill background jobs.

## Notes

- All connections are TLS by default; PGO provisions its own PKI.
- `replicas: 2` provides HA with automated failover via Patroni.
- Credentials live in the `hippo-pguser-hippo` secret (`uri`, `jdbc-uri`, `user`, `password`, `host`, `dbname`).
- For PostgreSQL 15+, the `hippo` user can create tables in its own schema without extra grants.
- Change `metadata.name`, `metadata.namespace`, storage sizes, and the `?ref=` tag to fit your environment. Latest v5 tags at time of writing: v5.8.8, v5.8.7, v5.8.6.
