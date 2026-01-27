from common import VulnSageReactAgent
from agentscope.service import ServiceToolkit
from configs import DASH_SCOPE_MODEL
from .service import installJsModule, executeJsCode, generateJsCode, findSanitizer, reflectSelfCritics,  \
    initJsEnvironment
from common.service import final_output


class TypeScriptAgent(VulnSageReactAgent):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    @classmethod
    def create(cls, sys_prompt="You are an expert programming assistant: {name}."):
        service_toolkit = ServiceToolkit()
        service_toolkit.add(installJsModule)
        service_toolkit.add(executeJsCode)
        service_toolkit.add(generateJsCode)
        service_toolkit.add(findSanitizer)
        service_toolkit.add(reflectSelfCritics)
        service_toolkit.add(final_output)
        service_toolkit.add(initJsEnvironment)

        return cls(
            name="VulnSage-Javascript-Agent",
            model_config_name=DASH_SCOPE_MODEL,
            sys_prompt=sys_prompt,
            verbose=True,
            max_iters=20,
            service_toolkit=service_toolkit,
        )
