import json
import logging
from typing import List, Dict

import requests

from agentscope.service import ServiceResponse, ServiceExecStatus
from configs import GlobalContext
from feeder import get_scan_feeder

logger = logging.getLogger("common")


def upload_scan_feeder(scan_feeder: List[Dict[str, str]]):
    url = f"{GlobalContext.openapi_remote_address}/uploadScanFeeder"
    payload = json.dumps({"scanFeeder": scan_feeder})
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }
    response = requests.request("POST", url, headers=headers, data=payload, timeout=1200)
    logger.info(response.text)
    return ServiceResponse(ServiceExecStatus.SUCCESS, json.loads(response.text))


def delete_work_env(task_id: str, session_id: str):
    url = f"{GlobalContext.openapi_remote_address}/deleteWorkEnv"
    payload = json.dumps({"taskId": task_id, "sessionId": session_id})
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }
    response = requests.request("POST", url, headers=headers, data=payload, timeout=120)
    return ServiceResponse(ServiceExecStatus.SUCCESS, json.loads(response.text))


def view_all_scan_feeder_id():
    url = f"{GlobalContext.openapi_remote_address}/viewAllScanFeederId"

    payload = json.dumps({})
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }

    response = requests.request("POST", url, headers=headers, data=payload, timeout=120)
    return ServiceResponse(ServiceExecStatus.SUCCESS, json.loads(response.text))


def auto_detect_task_id_all(scan_feeder: List[Dict[str, str]], remote_ip="http://127.0.0.1:8080"):
    """
    upload the scan_feeder and overwrite the remote scan_feeder
    :return:
    """
    collectors = []
    for _scan_feeder in scan_feeder:
        _task_id = _scan_feeder["task_id"]
        collectors.append(_scan_feeder)
    if len(collectors) > 0:
        remote_ip_bak = GlobalContext.openapi_remote_address
        GlobalContext.openapi_remote_address = remote_ip
        result = upload_scan_feeder(collectors)
        GlobalContext.openapi_remote_address = remote_ip_bak
        logger.info(result)


def auto_detect_task_id_exists(scan_feeder: List[Dict[str, str]]):
    """
    upload the scan_feeder and renew the remote scan_feeder

    :return:
    """
    result = view_all_scan_feeder_id()
    remote_task_ids = result.content
    added_remote_ids = []
    for _scan_feeder in scan_feeder:
        _task_id = _scan_feeder["task_id"]
        if _task_id not in remote_task_ids:
            added_remote_ids.append(_task_id)
    collectors = []
    for _scan_feeder in scan_feeder:
        _task_id = _scan_feeder["task_id"]
        if _task_id in added_remote_ids:
            collectors.append(_scan_feeder)
    if len(collectors) > 0:
        result = upload_scan_feeder(collectors)
        logger.info(result)


def final_output(taskId, lastScriptCode, reason, label, sanitizer=None):
    """
    Determine whether the vulnerability truly exists and provide the corresponding reason and output results finally.
    Args:
        taskId (`str`):
            The task id to search the function body.
        lastScriptCode (`str`):
            The last java code was executed.（do not modify anywhere）
        reason (`str`):
            The reason whether the vulnerability truly exists or not
        label (`str`):
            Whether the vulnerability exists (Y/N). Only fill in 'Y' if it has been successfully executed in the given environment.
        sanitizer (`str`):
            The sanitizer function to solve the vulnerability.[optional]
    Remember:
        check result must contain `taskId` field , `lastScriptCode` field and `label` field
    """
    scan_feeder = get_scan_feeder(taskId)
    if scan_feeder is None:
        return ServiceResponse(ServiceExecStatus.ERROR, "taskId not found")
    result = dict()
    result["label"] = label
    result["taskId"] = taskId
    result["lastScriptCode"] = lastScriptCode
    result["reason"] = reason
    if sanitizer is not None:
        result["sanitizer"] = sanitizer
    response = json.dumps(result, ensure_ascii=False)
    return ServiceResponse(ServiceExecStatus.SUCCESS, response)
