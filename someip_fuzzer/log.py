import csv
import logging
import os
import threading

logger = logging.getLogger("someip_fuzzer")
logger.setLevel(logging.DEBUG)

formatter = logging.Formatter("%(asctime)s %(levelname)s: %(message)s", "%H:%M:%S")

if not logger.handlers:
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    ch.setFormatter(formatter)
    logger.addHandler(ch)

lock = threading.Lock()
csv_lock = threading.Lock()


def log_debug(text):
    with lock:
        logger.debug(text)


def log_info(text):
    with lock:
        logger.info(text)


def log_warning(text):
    with lock:
        logger.warning(text)


def log_error(text):
    with lock:
        logger.error(text)


def log_csv_row(path, row, header=None):
    with csv_lock:
        file_exists = os.path.exists(path)
        with open(path, "a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            if header is not None and not file_exists:
                writer.writerow(header)
            writer.writerow(row)
