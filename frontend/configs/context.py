from .config import openapi_remote_address


class GlobalContext:
    openapi_remote_address: str = openapi_remote_address
    total_prompt_tokens: int = 0
    total_completion_tokens: int = 0