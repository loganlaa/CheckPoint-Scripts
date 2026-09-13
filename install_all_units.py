import argparse
import json
import os
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

# --- CONFIGURAÇÃO DE PRODUÇÃO ---
INPUT_FILE = "gateways_input.json"
SESSION_FILE = "mysession.txt"
EXECUTE_INSTALL = True
BATCH_SIZE = 5      # Máximo de instalações simultâneas

# Lista global para acumular falhas
FAILED_GATEWAYS_REPORT = []
PRINT_LOCK = Lock()


def safe_print(*args, **kwargs):
    """Evita que mensagens de instalações paralelas sejam misturadas."""
    with PRINT_LOCK:
        print(*args, **kwargs)


def extract_json_from_mixed_output(raw_text):
    try:
        return json.loads(raw_text)
    except (TypeError, ValueError):
        pass

    start = raw_text.find('{')
    end = raw_text.rfind('}')
    if start != -1 and end != -1:
        try:
            return json.loads(raw_text[start:end + 1])
        except (TypeError, ValueError):
            pass
    return None


def run_mgmt_cmd(cmd_list, session_file=None):
    base_cmd = ["mgmt_cli"]
    if session_file:
        base_cmd += ["-s", session_file]
    full_cmd = base_cmd + cmd_list + ["--format", "json"]
    try:
        result = subprocess.check_output(full_cmd, stderr=subprocess.STDOUT)
        raw_text = result.decode('utf-8', errors='replace')
        return extract_json_from_mixed_output(raw_text) or {"error_raw": raw_text}
    except subprocess.CalledProcessError as e:
        raw_output = e.output.decode('utf-8', errors='replace') if e.output else ""
        return extract_json_from_mixed_output(raw_output) or {"error_raw": raw_output}
    except OSError as e:
        # Por exemplo: mgmt_cli indisponível ou sem permissão de execução.
        return {"error_raw": str(e)}


def login_raw(api_key):
    safe_print("[-] Autenticando...")
    cmd = ["mgmt_cli", "login", "api-key", api_key, "--format", "json"]
    with open(SESSION_FILE, 'wb') as f:
        try:
            subprocess.check_call(cmd, stdout=f, stderr=sys.stderr)
            return True
        except (subprocess.CalledProcessError, OSError):
            return False


def check_task_status_adaptive(task_id):
    """Tenta consultar a tarefa usando id ou task-id."""
    res = run_mgmt_cmd(["show", "task", "id", task_id], SESSION_FILE)
    if res and "tasks" in res:
        return res

    err_code = res.get("code", "") if res else ""
    if "invalid_parameter" in err_code:
        res = run_mgmt_cmd(["show", "task", "task-id", task_id], SESSION_FILE)
        if res and "tasks" in res:
            return res
    return None


def wait_for_task(task_id, gateway_name):
    # Delay inicial necessário para o Management indexar a tarefa.
    safe_print(f"    [{gateway_name}] ... Aguardando processamento (Delay 5s) ...")
    time.sleep(5)
    errors_count = 0

    while True:
        res = check_task_status_adaptive(task_id)
        if not res or "tasks" not in res:
            errors_count += 1
            safe_print(f"    [{gateway_name}] [!] Tentando ler status ({errors_count}/10)...")
            if errors_count > 10:
                return False, "Timeout: API não retornou o status da tarefa. Verifique SmartConsole."
            time.sleep(3)
            continue

        task = res["tasks"][0]
        status = task.get("status", "unknown")
        progress = task.get("progress-percentage", 0)
        safe_print(f"    [{gateway_name}] Status: {status} ({progress}%)")

        if status == "succeeded":
            return True, "Sucesso completo."

        if status in ["failed", "partially-succeeded"]:
            reasons = []
            for detail in task.get("task-details", []):
                if detail.get("status") == "failed":
                    reason = detail.get("statusDescription", "")
                    if reason:
                        reasons.append(reason)
            if task.get("comments"):
                reasons.append(task["comments"])
            if not reasons:
                reasons.append("Verifique logs no SmartConsole (API não detalhou)")
            return False, " | ".join(dict.fromkeys(reasons))

        if status in ["in progress", "queued"]:
            time.sleep(3)
        else:
            return False, f"Status final desconhecido: {status}"


def is_cluster_member(obj):
    """Identifica membros de cluster sem confundir o objeto do cluster com seus membros."""
    obj_type = str(obj.get("type", "")).lower().replace("_", "-")
    if "cluster-member" in obj_type:
        return True

    # Dependendo da versão do Management API, a associação é devolvida como
    # flag booleana ou como referência ao cluster pai.
    member_flags = ("cluster-member", "cluster_member", "is-cluster-member", "is_cluster_member")
    if any(obj.get(flag) is True for flag in member_flags):
        return True

    parent_cluster_fields = ("cluster-uid", "cluster_uid", "cluster-name", "cluster_name")
    return any(obj.get(field) for field in parent_cluster_fields)


def generate_filtered_input():
    if os.path.exists(INPUT_FILE):
        os.remove(INPUT_FILE)
    safe_print("[-] Gerando inventário...")
    data = run_mgmt_cmd(
        ["show", "gateways-and-servers", "details-level", "full", "limit", "500"],
        SESSION_FILE,
    )
    formatted_list = []
    ignored_types = ['management-server', 'log-server', 'mds', 'checkpoint-host']
    excluded_cluster_members = []
    for obj in data.get("objects", []):
        o_type = obj.get('type', '').lower()
        if any(t in o_type for t in ignored_types):
            continue
        if is_cluster_member(obj):
            excluded_cluster_members.append(obj['name'])
            continue
        formatted_list.append({obj['name']: obj['uid']})
    with open(INPUT_FILE, 'w') as f:
        json.dump(formatted_list, f, indent=4)
    return excluded_cluster_members


def get_packages_map():
    safe_print("[-] Mapeando Políticas...")
    response = run_mgmt_cmd(
        ["show", "packages", "details-level", "full", "limit", "500"], SESSION_FILE
    )
    gw_policy_map = {}
    fallback_policy = None
    if "packages" in response:
        for pkg in response["packages"]:
            pkg_name = pkg["name"]
            targets = pkg.get("installation-targets", [])
            if targets == "all" or (isinstance(targets, list) and "all" in targets):
                fallback_policy = pkg_name
                continue
            if isinstance(targets, list):
                for target in targets:
                    target_uid = target if isinstance(target, str) else target.get("uid")
                    if target_uid:
                        gw_policy_map[target_uid] = pkg_name
    return gw_policy_map, fallback_policy


def get_api_error_message(response):
    """Converte respostas de erro JSON ou texto em uma mensagem para o relatório."""
    message = str(response.get("message", "")).strip()
    code = str(response.get("code", "")).strip()
    if message and code:
        return f"{message} (código: {code})"
    if message:
        return message
    if code:
        return f"Erro da API: {code}"
    if "error_raw" in response:
        return f"Erro no disparo da API: {response['error_raw'][:100]}..."
    return None


def install_gateway(entry):
    """Dispara e acompanha uma instalação; sempre retorna um resultado para o relatório."""
    gw_name = next(iter(entry))
    policy_name = entry[gw_name]["policy"]
    try:
        safe_print(f"[*] Gateway: {gw_name} | Política: {policy_name}")
        res = run_mgmt_cmd(
            [
                "install-policy", "policy-package", policy_name, "targets", gw_name,
                "access", "true", "threat-prevention", "true",
            ],
            SESSION_FILE,
        )

        task_id = res.get("task-id")
        if not task_id and res.get("tasks"):
            task_id = res["tasks"][0].get("task-id")

        if task_id:
            success, reason = wait_for_task(task_id, gw_name)
            if success:
                safe_print(f"    [{gw_name}] [SUCESSO REAL]")
                return {"name": gw_name, "policy": policy_name, "success": True}
            safe_print(f"    [{gw_name}] [FALHA REAL] {reason}")
            return {"name": gw_name, "policy": policy_name, "success": False, "reason": reason}

        err_msg = get_api_error_message(res)
        if err_msg:
            safe_print(f"    [{gw_name}] [ERRO API] {err_msg}")
            return {"name": gw_name, "policy": policy_name, "success": False, "reason": err_msg}

        safe_print(f"    [{gw_name}] [?] Falha no disparo: {res}")
        return {"name": gw_name, "policy": policy_name, "success": False, "reason": "Retorno desconhecido"}
    except Exception as e:
        err_msg = f"Erro inesperado durante a instalação: {e}"
        safe_print(f"    [{gw_name}] [ERRO INESPERADO] {err_msg}")
        return {"name": gw_name, "policy": policy_name, "success": False, "reason": err_msg}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--key', required=True)
    args = parser.parse_args()

    if not login_raw(args.key):
        sys.exit(1)

    try:
        excluded_cluster_members = generate_filtered_input()
        with open(INPUT_FILE, 'r') as f:
            gw_list = json.load(f)
        specific_map, fallback_policy = get_packages_map()

        valid_gateways_list = []
        safe_print("[-] Preparando lista...")
        skipped_count = 0
        for item in gw_list:
            gw_name = next(iter(item))
            gw_uid = item[gw_name]
            policy_name = specific_map.get(gw_uid, fallback_policy)
            if policy_name is None:
                skipped_count += 1
                continue
            valid_gateways_list.append({gw_name: {"uid": gw_uid, "policy": policy_name}})

        total_gws = len(valid_gateways_list)
        member_names = ", ".join(excluded_cluster_members) or "nenhum"
        safe_print(
            f"[-] Lista Final: {total_gws} gateways. Ignorados: {skipped_count}. "
            f"Membros de cluster ignorados: {len(excluded_cluster_members)} ({member_names})"
        )

        if EXECUTE_INSTALL and total_gws > 0:
            safe_print(f"\n[-] --- INICIANDO PRODUÇÃO (Batch Size: {BATCH_SIZE}) ---")
            batches = [valid_gateways_list[i:i + BATCH_SIZE] for i in range(0, total_gws, BATCH_SIZE)]
            total_batches = len(batches)

            for index, batch in enumerate(batches, start=1):
                safe_print(f"\n>>> BLOCO {index} de {total_batches} <<<")
                # Cada bloco tem no máximo cinco trabalhadores: todas as unidades do
                # bloco são disparadas e acompanhadas em paralelo antes do próximo.
                with ThreadPoolExecutor(max_workers=BATCH_SIZE) as executor:
                    futures = [executor.submit(install_gateway, entry) for entry in batch]
                    for future in as_completed(futures):
                        try:
                            result = future.result()
                        except Exception as e:  # Salvaguarda adicional para o relatório.
                            result = {
                                "name": "desconhecido", "policy": "desconhecida",
                                "success": False, "reason": f"Falha do trabalhador: {e}",
                            }
                        if not result["success"]:
                            FAILED_GATEWAYS_REPORT.append({
                                "name": result["name"], "policy": result["policy"],
                                "reason": result["reason"],
                            })

        # --- RELATÓRIO FINAL ---
        safe_print("\n" + "=" * 50)
        safe_print("RESUMO DA OPERAÇÃO")
        safe_print("=" * 50)
        safe_print(f"Total Processado: {total_gws}")
        safe_print(f"Sucessos: {total_gws - len(FAILED_GATEWAYS_REPORT)}")
        safe_print(f"Falhas:   {len(FAILED_GATEWAYS_REPORT)}")

        if FAILED_GATEWAYS_REPORT:
            safe_print("-" * 60)
            safe_print(f"{'GATEWAY':<25} | {'MOTIVO'}")
            safe_print("-" * 60)
            for fail in FAILED_GATEWAYS_REPORT:
                short_reason = (fail['reason'][:50] + '...') if len(fail['reason']) > 50 else fail['reason']
                safe_print(f"{fail['name']:<25} | {short_reason}")
        safe_print("=" * 50 + "\n")

    except Exception as e:
        safe_print(f"\n[!!!] Erro crítico: {e}")
    finally:
        if os.path.exists(SESSION_FILE):
            subprocess.call(
                ["mgmt_cli", "logout", "-s", SESSION_FILE],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            try:
                os.remove(SESSION_FILE)
            except OSError:
                pass


if __name__ == "__main__":
    main()
