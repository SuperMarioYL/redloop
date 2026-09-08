import json, pathlib, tempfile
from redloop.presets.demo import run_preset_demo
with tempfile.TemporaryDirectory(prefix="redloop-demo-") as folder:
    path = pathlib.Path(folder) / "hardening.jsonl"
    result = run_preset_demo(emit_path=path)
    records = [json.loads(line) for line in path.read_text().splitlines()]
    print(json.dumps({"target":"deterministic in-memory agent", "calls":[call.name for call in result.run.calls], "hijacked":result.hijacked, "severity":result.severity.value, "simulated_mailbox_entries":len(result.mailbox), "training_records":len(records), "record_fields":sorted(records[0])}, indent=2))
