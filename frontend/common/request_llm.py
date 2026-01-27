import json
import logging
from json import JSONDecodeError

from configs import DASH_SCOPE_MODEL, DASH_SCOPE_API_KEY, DASH_SCOPE_DEEPSEEK_V31, \
    DASH_SCOPE_QWEN3_MAX
from configs import GlobalContext
from openai import OpenAI

logger = logging.getLogger("common")


def token_count_wrapper(func):
    def wrapper(*args, **kwargs):
        raw_result = func(*args, **kwargs)
        try:
            result = raw_result["usage"]
        except JSONDecodeError as e:
            logger.warning(f"json decode error: {e}")
            return raw_result
        except IndexError as e:
            logger.warning(f"index error: {e}")
            return raw_result
        if "completion_tokens" in result and "prompt_tokens" in result and "total_tokens" in result:
            GlobalContext.total_completion_tokens += int(result["completion_tokens"])
            GlobalContext.total_prompt_tokens += int(result["prompt_tokens"])
        else:
            logger.warning("given column `completion_tokens`, `prompt_tokens` or `total_tokens` not in result")
        return raw_result

    return wrapper


@token_count_wrapper
def request_llm(
        system_content: str, user_content: str, model_name=DASH_SCOPE_MODEL
):
    model_name = DASH_SCOPE_QWEN3_MAX
    if model_name == DASH_SCOPE_DEEPSEEK_V31:
        return request_deepseek(system_content, user_content, model_name)
    else:
        return request_dashscope(system_content, user_content, model_name)


def request_deepseek(system_content: str, user_content: str, model_name=DASH_SCOPE_DEEPSEEK_V31) -> dict:
    client = OpenAI(
        api_key=DASH_SCOPE_API_KEY,
        base_url="https://dashscope.aliyuncs.com/compatible-mode/v1",
    )
    completion = client.chat.completions.create(
        model=model_name,
        messages=[
            {'role': 'system', 'content': system_content},
            {'role': 'user', 'content': user_content}
        ],
        extra_body={"enable_thinking": True},  # 必须开启思考
        stream_options={"include_usage": True},  # 必须开启 token 统计
        stream=True  # 必须流式，
    )

    reasoning_content = ""
    answer_content = ""
    final_usage = None
    is_answering = False

    for chunk in completion:
        # 检查是否有 choices（部分 chunk 可能为空）
        if hasattr(chunk, "usage") and chunk.usage is not None:
            # 最后一个 chunk 包含 usage
            if hasattr(chunk, "usage") and chunk.usage:
                final_usage = {
                    "prompt_tokens": chunk.usage.prompt_tokens,
                    "completion_tokens": chunk.usage.completion_tokens,
                    "total_tokens": chunk.usage.total_tokens
                }
            continue

        delta = chunk.choices[0].delta

        # 收集 thinking / reasoning 内容
        if hasattr(delta, "reasoning_content") and delta.reasoning_content is not None:
            if not is_answering:
                print(delta.reasoning_content, end="", flush=True)
            reasoning_content += delta.reasoning_content

        # 收到 content，进入回答阶段
        if hasattr(delta, "content") and delta.content:
            if not is_answering:
                is_answering = True
            answer_content += delta.content

    # ["choices"][0]["message"]["content"]
    return {
        "choices": [
            {
                "message": {
                    "content": answer_content
                }
            }
        ],
        "usage": final_usage
    }


def request_dashscope(system_content: str, user_content: str, model_name=DASH_SCOPE_MODEL) -> dict:
    client = OpenAI(
        api_key=DASH_SCOPE_API_KEY,
        base_url="https://dashscope.aliyuncs.com/compatible-mode/v1",
    )
    completion = client.chat.completions.create(
        model=DASH_SCOPE_MODEL,  # 模型列表：https://help.aliyun.com/zh/model-studio/getting-started/models
        messages=[
            {'role': 'system', 'content': system_content},
            {'role': 'user', 'content': user_content}],
        # extra_body={"enable_thinking": False, "stream": False},
    )
    return json.loads(completion.model_dump_json())
