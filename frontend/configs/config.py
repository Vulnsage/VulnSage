import json
import logging
import os
from pathlib import Path

import agentscope
from .log_config import init_log_config

init_log_config()
__logger = logging.getLogger("configs")

script_dir = Path(__file__).resolve().parent

VULN_SAGE_FRONTEND_ROOT_PATH = script_dir.parent.absolute()

__logger.info(f"VULN_SAGE_FRONTEND_ROOT_PATH: {VULN_SAGE_FRONTEND_ROOT_PATH}")
DASH_SCOPE_API_KEY: str = os.getenv("DASH_SCOPE_API_KEY", None)
if DASH_SCOPE_API_KEY is None:
    __logger.warning(f"DASH_SCOPE_API_KEY is None")
    exit(0)
SAMPOOL_TOKEN = os.getenv("SAMPOOL_TOKEN", None)
DASH_SCOPE_QWEN_CODER: str = "qwen-coder"
DASH_SCOPE_DEEPSEEK_R1: str = "deepseek-r1"
DASH_SCOPE_DEEPSEEK_V31: str = "deepseek-v3.1"
DASH_SCOPE_QWEN_MAX: str = "qwen-max"
DASH_SCOPE_QWEN3_MAX: str = "qwen3-max"
DASH_SCOPE_QWEN_PLUS: str = "qwen-plus"
DASH_SCOPE_QWEN_PLUS_0428 :str = "qwen-plus-2025-04-28"
DASH_SCOPE_QWEN_3: str = "qwen3-235b-a22b"

GPT4_O_MODEL: str = "gpt4o-1120"

DASH_SCOPE_MODEL: str = DASH_SCOPE_QWEN3_MAX

VULN_TYPE_COMMAND_INJECTION: str = "command_injection"
VULN_TYPE_SSRF: str = "ssrf"
VULN_TYPE_PROTOTYPE_POLLUTION: str = "prototype_pollution"
VULN_TYPE_JNDI: str = "jndi"
VULN_TYPE_CODE_INJECTION: str = "code_injection"
VULN_TYPE_PATH_TRAVERSAL: str = "path_traversal"
VULN_TYPE_PATH_TRAVERSAL_REMOTE_SERVER: str = "path_traversal_remote_server"

VULN_TYPE_COMMON: str = "common"
VULN_TYPE_PICKLE_INJECTION: str = "pickle_injection"


VULN_TYPE_STACK_OVER_FLOW_ERROR: str = "StackOverflowError"
VULN_TYPE_STRING_INDEX_OUT_OF_BOUNDS_EXCEPTION: str = "StringIndexOutOfBoundsException"
VULN_TYPE_NUMBER_FORMAT_EXCEPTION: str = "NumberFormatException"
VULN_TYPE_URL_REDIRECT: str = "UrlRedirect"

LANGUAGE_NODEJS: str = "nodejs"
LANGUAGE_JAVA: str = "java"
LANGUAGE_PYTHON: str = "python"

with open("configs/model_config.json", "r", encoding="utf-8") as f:
    model_configs = json.load(f)
    for model_config in model_configs:
        model_config["api_key"] = DASH_SCOPE_API_KEY

with open("configs/agent_config.json", "r", encoding="utf-8") as f:
    agent_configs = json.load(f)

agent_list = agentscope.init(
    model_configs=model_configs,
    agent_configs=agent_configs,
    project="VulnSage Agent",
)

openapi_remote_address = "http://47.243.76.86:8080"
SUCCESS_MESSAGE = "well done! the vulnerable has been proved , please finish the task!"
HACKER_PASSED_MESSAGE = "pass"
