from queue import Queue
from datetime import datetime
import os
import signal
import time

from someip_fuzzer.config import config
from someip_fuzzer.fuzzer import Fuzzer
from someip_fuzzer.heartbeat import Heartbeat
from someip_fuzzer.log import log_info, log_error
from someip_fuzzer.template import Template
from someip_fuzzer.types import NoHeartbeatError, NoHostError, NoSudoError, ServiceShutdown


def reload_config_file(path="config.ini"):
    config.clear()
    config.read(path, encoding="utf-8")


def import_template():
    generator = Template()
    return generator.read_template()


def shutdown(signum, frame):
    raise ServiceShutdown("Caught signal %d" % signum)


def extract_fields(template_obj, layer_name):
    """
    현재 playground_fields.json 구조(list[dict])와
    예전 tuple-key dict 구조를 둘 다 지원.
    """
    if isinstance(template_obj, list):
        for item in template_obj:
            if not isinstance(item, dict):
                continue
            if item.get("outgoing") is True and item.get("layer") == layer_name:
                return item["fields"]

    if isinstance(template_obj, dict):
        tuple_key = (True, layer_name)
        if tuple_key in template_obj:
            return template_obj[tuple_key]["fields"]

        str_key = str(tuple_key)
        if str_key in template_obj:
            return template_obj[str_key]["fields"]

        alt_key = f"{True},{layer_name}"
        if alt_key in template_obj:
            return template_obj[alt_key]["fields"]

        if layer_name in template_obj and isinstance(template_obj[layer_name], dict) and "fields" in template_obj[layer_name]:
            return template_obj[layer_name]["fields"]

    raise KeyError(f"Could not find fields for layer={layer_name}")


def resolve_log_csv_path():
    base_log_csv = config["Run"].get("LogCsv", fallback="results/results.csv").strip()

    dirname = os.path.dirname(base_log_csv)
    basename = os.path.basename(base_log_csv)
    root, ext = os.path.splitext(basename)

    if ext == "":
        ext = ".csv"

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    resolved_name = f"{root}_{timestamp}{ext}"

    if dirname:
        os.makedirs(dirname, exist_ok=True)
        return os.path.join(dirname, resolved_name)

    return resolved_name


def apply_runtime_overrides(overrides=None):
    if not overrides:
        return

    for section, values in overrides.items():
        if not config.has_section(section):
            config.add_section(section)
        for key, value in values.items():
            config[section][key] = str(value)


def run_campaign(config_path="config.ini", overrides=None):
    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    reload_config_file(config_path)
    apply_runtime_overrides(overrides)

    excq = Queue()
    threads = []
    targets = []

    template = import_template()
    fields = extract_fields(template, config["Fuzzer"]["Layer"]).items()

    resolved_log_csv = resolve_log_csv_path()
    config["Run"]["LogCsv"] = resolved_log_csv
    log_info("Resolved LogCsv path: {}".format(resolved_log_csv))

    for fieldname, fieldvalues in fields:
        fuzzer = fieldvalues["fuzzing"]["fuzzer"]
        if fuzzer is not None:
            targets.append((fieldname, fuzzer))
            log_info(
                "Fuzzing protocol layer '{}' on protocol field '{}'".format(
                    config["Fuzzer"]["Layer"], fieldname
                )
            )

    if config["Fuzzer"]["Mode"] != "replay":
        log_info("live mode is not implemented yet")
        return resolved_log_csv

    try:
        hb = Heartbeat(excq)
        threads.append(hb)

        for i in range(len(targets)):
            threads.append(Fuzzer(i, excq, template, targets[i]))

        for t in threads:
            t.start()

        duration_sec = config["Run"].getint("DurationSec", fallback=0)
        deadline = None
        if duration_sec > 0:
            deadline = time.time() + duration_sec
            log_info("Campaign deadline set to {} sec".format(duration_sec))

        while True:
            if excq.qsize() != 0:
                raise excq.get()

            if deadline is not None and time.time() >= deadline:
                log_info("Duration reached, stopping campaign")
                break

            fuzzer_threads = [t for t in threads if isinstance(t, Fuzzer)]
            fuzzer_alive = [t for t in fuzzer_threads if t.is_alive()]

            if deadline is None and len(fuzzer_threads) > 0 and len(fuzzer_alive) == 0:
                log_info("All fuzzer threads finished")
                break

            time.sleep(0.2)

    except (NoHostError, NoHeartbeatError, NoSudoError) as exc:
        log_error(exc)
    except ServiceShutdown as msg:
        log_info(msg)
    finally:
        for t in threads:
            t.shutdown.set()

        for t in threads:
            t.join()

        log_info("Exiting run_campaign()")

    return resolved_log_csv
