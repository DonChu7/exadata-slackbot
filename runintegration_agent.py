import subprocess
import os
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed



RUNTABLE_PATH = "/net/10.32.19.91/export/exadata_images/ImageTests/daily_runs_1/OSS_MAIN/runtable"
CONNECT_FILE = "/net/10.32.19.91/export/exadata_images/ImageTests/.pxeqa_connect"

def parse_runtable_lines(rack_name: str) -> list:
    """Return all lines from runtable matching the given rack name."""
    try: 
        result = subprocess.run(["grep", rack_name, RUNTABLE_PATH], capture_output=True, text=True, check=True)
        lines = result.stdout.strip().split("\n")
        return [line for line in lines if line.strip()]
    except subprocess.CalledProcessError:
        return []


def check_marker_status(entry: str, ssh_timeout: int = 3) -> str | None:
    """
    Return None if idle; otherwise a human-readable string for the running job.
    Performs ONE SSH call with strict timeouts.
    """
    fields = entry.strip().split(";")
    if len(fields) < 8:
        return None

    status, full_rack_name, _, _, client_ip, user_id, view_name, _ = fields[:8]

    if status == "disabled":
        return f"Environment {full_rack_name} is currently disabled from the runtable."

    marker_path = f"/scratch/{user_id}/image_oeda_upgrade_logs/{view_name}/markers/imagecron.running.marker"
    ssh_common = [
        "ssh", "-i", CONNECT_FILE,
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", f"ConnectTimeout={ssh_timeout}",
        "-o", f"ServerAliveInterval={ssh_timeout}",
        "-o", "ServerAliveCountMax=1",
        f"{user_id}@{client_ip}",
    ]
    remote = (
        f'if [ -f "{marker_path}" ]; then '
        f'  printf "RUNNING "; cat "{marker_path}"; '
        f'else '
        f'  echo "IDLE"; '
        f'fi'
    )
    try:
        out = subprocess.check_output(ssh_common + [remote], stderr=subprocess.DEVNULL, text=True).strip()
    except subprocess.CalledProcessError:
        # unreachable host → treat as idle
        return None

    if not out or out.startswith("IDLE"):
        return None

    parts = out.split()
    if len(parts) >= 5 and parts[0] == "RUNNING":
        job_name, submit_info, job_id, label_series = parts[1:5]
        submitter, submit_time = (submit_info.split("@", 1) + ["?"])[:2]
        return (f"The env {full_rack_name} is currently running job {job_name} on {label_series} "
                f"submitted by {submitter} at {submit_time}, the job id is {job_id}.")
    return f"The env {full_rack_name} is currently running a job, but marker format is unrecognized: {out[:120]}..."

# --- NEW: concurrent idle scanner ---
def get_idle_envs_concurrent(max_workers: int = 24, ssh_timeout: int = 3, per_host_limit: int | None = None):
    """
    Faster idle scan using a thread pool.
    - max_workers: overall parallelism
    - ssh_timeout: per-ssh connect timeout seconds
    - per_host_limit: optional cap of concurrent checks per (user@ip)
    """
    try:
        result = subprocess.run(["grep", "^enabled;", RUNTABLE_PATH], capture_output=True, text=True, check=True)
        lines = [l for l in result.stdout.strip().split("\n") if l.strip()]
    except subprocess.CalledProcessError:
        return "Failed to retrieve enabled environments."

    idle_envs = []
    seen = set()

    semaphores = {}
    def host_key(entry: str):
        f = entry.strip().split(";")
        return f"{f[5]}@{f[4]}" if len(f) >= 6 else "unknown"

    def task(entry: str):
        hk = host_key(entry)
        sem = None
        if per_host_limit and hk != "unknown":
            sem = semaphores.setdefault(hk, threading.Semaphore(per_host_limit))
            sem.acquire()
        try:
            return entry, check_marker_status(entry, ssh_timeout=ssh_timeout)
        finally:
            if sem:
                sem.release()

    futures = []
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        for line in lines:
            f = line.strip().split(";")
            if len(f) < 8:
                continue
            full_rack_name, deploy_type = f[1], f[3]
            key = (full_rack_name, deploy_type)
            if key in seen:
                continue
            seen.add(key)
            futures.append(ex.submit(task, line))

        for fut in as_completed(futures):
            entry, msg = fut.result()
            f = entry.strip().split(";")
            full_rack_name, deploy_type = f[1], f[3]
            if not msg:
                idle_envs.append({"rack_name": full_rack_name, "deploy_type": deploy_type})

    return idle_envs if idle_envs else "No idle environments available at the moment."


def check_runintegration_status(rack_name: str, ssh_timeout: int = 3) -> str:
    entries = parse_runtable_lines(rack_name)
    if not entries:
        return f"Given rack ({rack_name}) is not found in the runtable."

    for entry in entries:
        result = check_marker_status(entry, ssh_timeout=ssh_timeout)
        if result:
            return result
    return f"No job is currently running on env {rack_name}, and the env is idle."

def get_disabled_envs() -> list:
    try:
        result = subprocess.run(["grep", "^disabled;", RUNTABLE_PATH], capture_output=True, text=True, check=True)
        lines = result.stdout.strip().split("\n")
        if not lines:
            return []

        formatted = [
            f"{line.split(';')[1]} : {line.split(';')[3]}"
            for line in lines if len(line.split(";")) >= 4
        ]
        return formatted
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Failed to grep disabled envs: {e}")
        return []
