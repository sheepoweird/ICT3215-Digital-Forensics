"""Short-lived file operations. File keys and recovery secrets stay in this process."""

import json
import sys

import token_comms
import vault
import vault_v2
from crypto_engine import INDEX_HASH, environment_hash
from signals import collect_all_signals
from winutils import restore_worker_streams as _restore_worker_streams


def live_environment(signal_ids):
    available = {signal.id: signal for signal in collect_all_signals()}
    selected = []
    for signal_id in signal_ids:
        signal = available.get(signal_id)
        if signal is None or not signal.available or not signal.value:
            raise vault.VaultError("A required environment signal is unavailable.")
        selected.append(signal)
    if not selected:
        raise vault.VaultError("Select at least one environment signal.")
    return environment_hash(selected)


def main():
    _restore_worker_streams()
    try:
        request = json.load(sys.stdin)
        action = request["action"]
        if action == "open":
            key = token_comms.request_vault_key("metadata", bytes.fromhex(request["context"]))
            print(json.dumps({"result": key.hex()}))
            return 0
        path = request["path"]
        code = request.get("recovery_code")
        meta = vault_v2._meta(path)
        if code:
            session = vault_v2.unlock_recovery(path, code, local=True)
        else:
            # The GUI already authenticated the signal IDs when it opened the list.
            # Low-level callers without that list can retrieve it through the paired token.
            signal_ids = request.get("signal_ids")
            if signal_ids is None:
                signal_ids = vault_v2.read_signal_ids(path, token_comms.request_env_key(INDEX_HASH))
            if live_environment(signal_ids).hex() != meta["env_hash"]:
                raise vault.VaultError("The vault environment has changed.")
            session = vault_v2.Vault(path, bytes.fromhex(request["metadata_key"]), local=True)
        try:
            if action == "import":
                result = session.add_files(request["sources"], shred_original=request["shred_original"])
            elif action == "export":
                result = session.export_many(request["blobs"], request["destination"], recovery_code=code,
                                             temporary_dir=request.get("temporary_dir"))
            else:
                raise vault.VaultError("Unknown vault operation.")
        finally:
            session.lock()
        print(json.dumps({"result": result}))
    except Exception as exc:
        message = str(exc) or "Authentication failed. The file or recovery code may be incorrect."
        print(json.dumps({"error": message}))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
