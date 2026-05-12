import configparser

CONFIG_PATH = "config.ini"

config = configparser.ConfigParser()


def reload_config(path=CONFIG_PATH):
    config.clear()
    config.read(path, encoding="utf-8")
    return config


reload_config()
