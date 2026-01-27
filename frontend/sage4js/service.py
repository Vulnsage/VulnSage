import json
import logging
import re

import requests

from agentscope.service import ServiceResponse, ServiceExecStatus
from common import check_code_hacker, request_llm, get_last_x_lines
from configs import SUCCESS_MESSAGE, GlobalContext, LANGUAGE_NODEJS, VULN_TYPE_COMMON, HACKER_PASSED_MESSAGE
from feeder import get_scan_feeder
from prompting import PromptTemplateLoader

logger = logging.getLogger("sage4js")


def generateJsCode(taskId):
    """Generate javascript code for the given task id. Extra parameters will be passed to the function if needed.

    Args:
        taskId (`str`):
            The task id to search the function body.
    """
    scan_feeder = get_scan_feeder(taskId)
    if scan_feeder is None:
        return ServiceResponse(ServiceExecStatus.SUCCESS, "taskId not found")

    
    detailed_trace = scan_feeder["detailed_trace"]
    call_chain = scan_feeder["trace"]
    last_constraint = ""
    response = ""
    for trace_code in detailed_trace:
        user_prompt = PromptTemplateLoader.get_user_template(LANGUAGE_NODEJS, scan_feeder["task_type"],
                                                             "code_generate_code_audit")
        system_prompt = PromptTemplateLoader.get_system_template(LANGUAGE_NODEJS, scan_feeder["task_type"],
                                                                 "code_generate_code_audit")
        user_prompt_init = user_prompt.render(
            last_constraint=last_constraint,
            template=scan_feeder["template"],
            call_chain=call_chain,
            trace_code=trace_code + "\n" + detailed_trace[trace_code],
            class_constructors=scan_feeder["class_constructors"],
        )
        result = request_llm(system_prompt.render(), user_prompt_init)
        response = result["choices"][0]["message"]["content"]
        last_constraint = format(response)
        print(">>>>>>>>>>>>>last_constraint")
        print(last_constraint)
    constraints = response

    
    user_prompt = PromptTemplateLoader.get_user_template(LANGUAGE_NODEJS, scan_feeder["task_type"],
                                                         "code_generate_without_last_reason")
    system_prompt = PromptTemplateLoader.get_system_template(LANGUAGE_NODEJS, scan_feeder["task_type"],
                                                             "code_generate_without_last_reason")
    result = request_llm(system_prompt.render(),
                          user_prompt.render(
                              template=scan_feeder["template"],
                              trace=scan_feeder["trace"],
                              code=scan_feeder["detailed_trace"],
                              class_constructors=scan_feeder["class_constructors"],
                              constraints=constraints
                          ))
    response = result["choices"][0]["message"]["content"]
    response += """
    <iternum> 1 </iternum>
    Furthermore, you should invoke `executeJsCode` function with taskId, code and sessionId parameters.
    """
    return ServiceResponse(ServiceExecStatus.SUCCESS, response)


def executeJsCode(taskId: str, scriptCode: str, sessionId: str, iternum: int):
    """Execute javascript code, system will use built-in javascript to execute the code. The code should follow the given template

    Args:
        taskId (`str`):
            The task id to search the function body.
        scriptCode (`str`):
            The typescript code to be executed. Do not use ``` or [] to wrap the code. Do not add any annotation.
        sessionId (`str`):
            The session id to redirect to current javascript environment.
        iternum (`int`):
            The number of attempt rounds. (Directly pass in the iternum from the previous round, no need to increment)
    """
    scan_feeder = get_scan_feeder(taskId)
    if scan_feeder is None:
        return ServiceResponse(ServiceExecStatus.ERROR, "taskId not found")

    detect_result = check_code_hacker(scriptCode, scan_feeder["task_type"], LANGUAGE_NODEJS)
    if detect_result != HACKER_PASSED_MESSAGE:
        result = ""
        result += "<lastScript>\n" + scriptCode + "\n</lastScript>\n"
        result += "<failReason>\n" + detect_result + " Strictly follow the given template to generate PoC." + "\n</failReason>"
        result += "\n\nFurthermore, you should invoke `reflectSelfCritics` function with taskId, lastScriptCode and failReason parameters."
        logger.warning("result" + result)
        return ServiceResponse(ServiceExecStatus.SUCCESS, result)

    url = f"{GlobalContext.openapi_remote_address}/executeJsCode"

    payload = json.dumps({
        "taskId": taskId,
        "code": scriptCode,
        "sessionId": str(sessionId)
    })
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }
    response = requests.request("POST", url, headers=headers, data=payload, timeout=60)
    jsonResult = json.loads(response.content)["result"]

    if SUCCESS_MESSAGE in response.text:
        return ServiceResponse(ServiceExecStatus.SUCCESS, SUCCESS_MESSAGE)
    else:
        result = ""
        if "lastScript" in jsonResult.keys():
            result += "<lastScript>\n" + jsonResult["lastScript"] + "\n</lastScript>"
            result += "\n"
        if "lastReason" in jsonResult.keys():
            
            if "EXECUTION_TRACE:" in jsonResult["lastReason"]:
                errlog = jsonResult["lastReason"].split("EXECUTION_TRACE:", 1)
                stderr = errlog[0]
                execution_trace = errlog[1]
            else:
                stderr = jsonResult["lastReason"]
                execution_trace = ""
            if len(stderr) > 500:
                user_prompt = PromptTemplateLoader.get_user_template(LANGUAGE_NODEJS, VULN_TYPE_COMMON,
                                                                     "clean_fail_reason")
                system_prompt = PromptTemplateLoader.get_system_template(LANGUAGE_NODEJS, VULN_TYPE_COMMON,
                                                                         "clean_fail_reason")
                clean_reason = request_llm(system_prompt.render(), user_prompt.render(log=stderr))
                clean_reason = clean_reason["choices"][0]["message"]["content"]
            else:
                clean_reason = stderr
            if "EXECUTION_TRACE:" in jsonResult["lastReason"]:
                result += ("<failReason>\n" + clean_reason + "\nEXECUTION_TRACE (截取最末端20行，请关注最后的断点报错处):\n"
                           + get_last_x_lines(execution_trace, 20) + "\n</failReason>")
            else:
                result += "<failReason>\n" + clean_reason + "\n</failReason>"

    
    result += "\n\n<iternum>" + str(iternum) + "</iternum>"
    if iternum < 6:
        
        pattern = r"package\s+([a-zA-Z_][a-zA-Z0-9_]*(\.[a-zA-Z_][a-zA-Z0-9_]*)+)\s+does not exist"
        matches = re.findall(pattern, result)
        if matches:
            result += "\n\nFurthermore, you should invoke `installJsModule` function with taskId, moduleName and sessionId parameters."
        
        else:
            result += "\n\nFurthermore, you should invoke `reflectSelfCritics` function with taskId, lastScriptCode and failReason parameters."
    else:
        result += "\n\nFurthermore, you should invoke `findSanitizer` function "
    
    return ServiceResponse(ServiceExecStatus.SUCCESS, result)


def reflectSelfCritics(taskId, lastScriptCode, failReason, iternum):
    """
    Analyze the failure reason based on the issues shown in STDOUT and STDERR, re-read the code, modify the previous PoC, and generate new executable code.
    Args:
        taskId (`str`):
            The task id to search the function body.
        lastScriptCode (`str`):
            The last script code to be executed.
        failReason (`str`):
            The fail reason to analyze.
        iternum (`int`):
            The number of attempt rounds. (Directly pass in the iternum from the previous round, no need to increment)
        """
    scan_feeder = get_scan_feeder(taskId)
    if scan_feeder is None:
        return ServiceResponse(ServiceExecStatus.ERROR, "taskId not found")
    user_prompt = PromptTemplateLoader.get_user_template(LANGUAGE_NODEJS, scan_feeder["task_type"],
                                                         "code_generate_with_last_reason")
    system_prompt = PromptTemplateLoader.get_system_template(LANGUAGE_NODEJS, scan_feeder["task_type"],
                                                             "code_generate_with_last_reason")
    result = request_llm(system_prompt.render(),
                          user_prompt.render(
                              template=scan_feeder["template"],
                              trace=scan_feeder["trace"],
                              code=scan_feeder["detailed_trace"],
                              class_constructors=scan_feeder["class_constructors"],
                              lastScriptCode=lastScriptCode,
                              failReason=failReason,
                          ))
    response = result["choices"][0]["message"]["content"]
    response += "\n\n<iternum>" + str(iternum + 1) + "</iternum>"
    response += """
    Furthermore, you should invoke `executeJsCode` function with taskId, code and sessionId parameters.
    """
    return ServiceResponse(ServiceExecStatus.SUCCESS, response)


def findSanitizer(taskId, lastScriptCode, failReason):
    """
    analyze the code to identify the key function causing the PoC failure, prove that the vulnerability does not exist, and return the reason.
    Args:
        taskId (`str`):
            The task id to search the function body.
        lastScriptCode (`str`):
            The last java code was executed.（do not modify anywhere）
        failReason (`str`):
            The fail reason while excute lastScript, may contain STDOUT and STDERR.
    """
    scan_feeder = get_scan_feeder(taskId)
    if scan_feeder is None:
        return ServiceResponse(ServiceExecStatus.ERROR, "taskId not found")
    user_prompt = PromptTemplateLoader.get_user_template(LANGUAGE_NODEJS, VULN_TYPE_COMMON,
                                                         "find_sanitizer")
    system_prompt = PromptTemplateLoader.get_system_template(LANGUAGE_NODEJS, VULN_TYPE_COMMON,
                                                             "find_sanitizer")
    result = request_llm(system_prompt.render(),
                          user_prompt.render(
                              template=scan_feeder["template"],
                              trace=scan_feeder["trace"],
                              code=scan_feeder["detailed_trace"],
                              class_constructors=scan_feeder["class_constructors"],
                              lastScriptCode=lastScriptCode,
                              failReason=failReason,
                          ))
    response = result["choices"][0]["message"]["content"]
    response += """
    Furthermore, you should invoke `final_output` function with taskId, lastScriptCode, failReason, sanitizer and reason.
    """
    return ServiceResponse(ServiceExecStatus.SUCCESS, response)


def initJsEnvironment(taskId, sessionId):
    """Initialize the javascript environment.
    Args:
        taskId (`str`):
            The task id to search the function body.
        sessionId (`str`):
            The session id to redirect to current javascript environment.
    """
    url = f"{GlobalContext.openapi_remote_address}/initJsEnvironment"
    payload = json.dumps({
        "taskId": taskId,
        "sessionId": sessionId
    })
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }
    response = requests.request("POST", url, headers=headers, data=payload, timeout=60)
    return ServiceResponse(ServiceExecStatus.SUCCESS, json.loads(response.content)["result"])


def installJsModule(taskId, moduleName, sessionId):
    """Install the module (npm package) in the TypeScript environment.

    Args:
        taskId (`str`):
            The task id to search the function body.
        moduleName (`str`):
            The module name to install.
        sessionId (`str`):
            The session id to redirect to current javascript environment.
    """
    url = f"{GlobalContext.openapi_remote_address}/installJsModule"
    scan_feeder = get_scan_feeder(taskId)
    if scan_feeder["package_name"][0:scan_feeder["package_name"].rindex("@")] == moduleName:
        logger.info(f"moduleName changed from {moduleName} to {scan_feeder["package_name"]} ")
        moduleName = scan_feeder["package_name"]
    payload = json.dumps({
        "taskId": taskId,
        "moduleName": moduleName,
        "sessionId": sessionId
    })
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }

    response = requests.request("POST", url, headers=headers, data=payload, timeout=60)
    return ServiceResponse(ServiceExecStatus.SUCCESS, json.loads(response.content)["result"])
