import json
import logging
from pathlib import Path
from typing import Dict, Union

from configs import (
    VULN_TYPE_COMMAND_INJECTION,
    VULN_TYPE_PROTOTYPE_POLLUTION,
    VULN_TYPE_JNDI,
    VULN_TYPE_CODE_INJECTION, VULN_TYPE_PICKLE_INJECTION, VULN_TYPE_PATH_TRAVERSAL,
)

logger = logging.getLogger("feeder")

script_dir = Path(__file__).resolve().parent

file_path = script_dir / "scanFeeder.json"

GENERAL_VULN_TYPE_TO_BUILTIN_DICT = {
    "PrototypePollutionTs": VULN_TYPE_PROTOTYPE_POLLUTION,
    "CommandExecutionTs": VULN_TYPE_COMMAND_INJECTION,
    "CommandInjectionTs": VULN_TYPE_COMMAND_INJECTION,
    "CommandInjectionJava": VULN_TYPE_COMMAND_INJECTION,
    "JNDIECR": VULN_TYPE_JNDI,
    "DirectECR": VULN_TYPE_COMMAND_INJECTION,
    "MavenDirectRce": VULN_TYPE_COMMAND_INJECTION,
    "Code_Injection_NodeJs_Taint_ECR": VULN_TYPE_CODE_INJECTION,
    "Command_Injection_NodeJs_Taint_ECR": VULN_TYPE_COMMAND_INJECTION,
    VULN_TYPE_COMMAND_INJECTION: VULN_TYPE_COMMAND_INJECTION,
    VULN_TYPE_PROTOTYPE_POLLUTION: VULN_TYPE_PROTOTYPE_POLLUTION,
    VULN_TYPE_PICKLE_INJECTION: VULN_TYPE_PICKLE_INJECTION,
    "prototypePollutionAssignment": VULN_TYPE_PROTOTYPE_POLLUTION,
    "prototypePollutionFunction": VULN_TYPE_PROTOTYPE_POLLUTION,
    "prototypePollutionMergeCall": VULN_TYPE_PROTOTYPE_POLLUTION,
    "jndi": VULN_TYPE_JNDI,
    'Python_Deserialization': VULN_TYPE_PICKLE_INJECTION,
    "path_traversal": VULN_TYPE_PATH_TRAVERSAL,
    VULN_TYPE_CODE_INJECTION: VULN_TYPE_CODE_INJECTION,
    "Pathtravel_Nodejs_Taint": VULN_TYPE_PATH_TRAVERSAL
}

with open(file_path, "r") as f:
    scan_feeders = json.load(f)

scan_feeders_reformat = []
for scan_feeder in scan_feeders:
    task_type = scan_feeder["task_type"]
    if task_type not in GENERAL_VULN_TYPE_TO_BUILTIN_DICT.keys():
        raise ValueError(f"task_type {task_type} not found")
    scan_feeder["task_type"] = GENERAL_VULN_TYPE_TO_BUILTIN_DICT[task_type]
    scan_feeders_reformat.append(scan_feeder)
scan_feeders = scan_feeders_reformat

_SCAN_FEEDER_MATERIAL: Dict[str, Dict[str, str]] = {}
for scan_feeder in scan_feeders:
    _SCAN_FEEDER_MATERIAL[scan_feeder["task_id"]] = scan_feeder


def get_scan_feeder(task_id) -> Union[Dict, None]:
    if task_id not in _SCAN_FEEDER_MATERIAL.keys():
        logger.warning(f"task_id {task_id} not found")
        return None
    return _SCAN_FEEDER_MATERIAL[task_id]


def get_scan_feeder_size() -> int:
    return len(_SCAN_FEEDER_MATERIAL)


def get_scan_feeder_keys() -> list:
    return list(_SCAN_FEEDER_MATERIAL.keys())


def reload_scan_feeder(_file_path: str):
    global _SCAN_FEEDER_MATERIAL
    if not Path(_file_path).exists():
        raise ValueError(f"file {_file_path} not found")
    with open(_file_path, "r") as f:
        _scan_feeders = json.load(f)
    _SCAN_FEEDER_MATERIAL = {}
    for _scan_feeder in _scan_feeders:
        _task_type = _scan_feeder["task_type"]
        if _task_type not in GENERAL_VULN_TYPE_TO_BUILTIN_DICT.keys():
            raise ValueError(f"task_type {_task_type} not found")
        _scan_feeder["task_type"] = GENERAL_VULN_TYPE_TO_BUILTIN_DICT[_task_type]
        _SCAN_FEEDER_MATERIAL[_scan_feeder["task_id"]] = _scan_feeder
