import json
import logging
from typing import Dict, Tuple

from agentscope.message import Msg
from common import TaskIdNotFoundError, auto_detect_task_id_all, VulnSageReactAgent
from configs import GlobalContext, LANGUAGE_NODEJS, LANGUAGE_JAVA, SUCCESS_MESSAGE
from feeder import get_scan_feeder, get_scan_feeder_keys
from prompting import PromptTemplateLoader
from sage4j import JavaAgent
from sage4js import TypeScriptAgent

LOADED_AGENTS: Dict[str, VulnSageReactAgent] = {
    LANGUAGE_NODEJS: TypeScriptAgent,
    LANGUAGE_JAVA: JavaAgent,
}
T = Tuple[str, str, str, int, int, int]

logger = logging.getLogger(__name__)


def single_run(task_id, session_id, language, remote_ip="http://127.0.0.1:8080") -> T:
    scan_feeder = get_scan_feeder(task_id)
    if scan_feeder is None:
        raise TaskIdNotFoundError(task_id)
    if language not in [LANGUAGE_NODEJS, LANGUAGE_JAVA]:
        raise ValueError(f"language {language} not supported")
    GlobalContext.openapi_remote_address = remote_ip
    GlobalContext.total_completion_tokens = 0
    GlobalContext.total_prompt_tokens = 0
    user_prompt = PromptTemplateLoader.get_user_template(language, scan_feeder["task_type"], "init_script")
    system_prompt = PromptTemplateLoader.get_system_template(language, scan_feeder["task_type"], "init_script")
    input_msg = Msg(content=user_prompt.render(
        template=scan_feeder["template"],
        task_id=task_id,
        session_id=session_id,
        package_name=scan_feeder["package_name"],
        language=language
    ), role="user", name="User")
    agent = LOADED_AGENTS[language].create(sys_prompt=system_prompt.render())
    x = agent(input_msg)
    logger.info(f"output: {x.content}")
    memory = agent.get_final_memory()
    token_list = agent.get_final_token()
    assert token_list.__len__() == 1
    times, prompt_tokens, completion_tokens \
        = int(token_list[0]["times"]), int(token_list[0]["prompt_tokens"]), int(token_list[0]["completion_tokens"])
    logger.info(f"memory: {memory}")
    output = agent.output()
    logger.info("<== agent output ==> %s" % output)
    try:
        output_json = json.loads(output)
        if SUCCESS_MESSAGE in memory.__str__():
            output_json["label"] = "Y"
        else:
            output_json["label"] = "N"
    except Exception as e:
        if SUCCESS_MESSAGE in memory.__str__():
            output_json = {"label": "Y"}
        else:
            output_json = {"label": "N"}
    logger.info(f"output_json: {output_json},"
                f"total_prompt_tokens: {GlobalContext.total_prompt_tokens + prompt_tokens},"
                f"total_completion_tokens: {GlobalContext.total_completion_tokens + completion_tokens}")
    return (
        x.content,
        memory,
        json.dumps(output_json, indent=4),
        GlobalContext.total_prompt_tokens + prompt_tokens,
        GlobalContext.total_completion_tokens + completion_tokens,
        times,
    )


def single_run_for_ts(task_id, session_id, remote_ip="http://127.0.0.1:8080") -> T:
    return single_run(task_id, session_id, LANGUAGE_NODEJS, remote_ip)


def single_run_for_java(task_id, session_id, remote_ip="http://127.0.0.1:8080") -> T:
    return single_run(task_id, session_id, LANGUAGE_JAVA, remote_ip)


if __name__ == '__main__':
    auto_detect_task_id_all([get_scan_feeder(i) for i in get_scan_feeder_keys()],
                            remote_ip="http://127.0.0.1:8080")
    a = single_run_for_ts(
        "apidoc-core@0.15.0_0", "abc",
        remote_ip="http://127.0.0.1:8080",
    )
