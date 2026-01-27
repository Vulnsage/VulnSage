from agentscope.service import ServiceToolkit
from common import VulnSageReactAgent
from common.service import final_output
from configs import DASH_SCOPE_MODEL
from .service import installJavaPackage, executeJavaCode, generateJavaCode, reflectSelfCritics, findSanitizer, \
    initJavaEnvironment


class JavaAgent(VulnSageReactAgent):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    @classmethod
    def create(cls, sys_prompt="You are an expert programming assistant: {name}."):
        service_toolkit = ServiceToolkit()
        service_toolkit.add(installJavaPackage)
        service_toolkit.add(initJavaEnvironment)
        service_toolkit.add(executeJavaCode)
        service_toolkit.add(generateJavaCode)
        service_toolkit.add(reflectSelfCritics)
        service_toolkit.add(findSanitizer)
        service_toolkit.add(final_output)
        agent = cls(
            name="VulnSage-Java-Agent",
            model_config_name=DASH_SCOPE_MODEL,
            sys_prompt=sys_prompt,
            verbose=True,
            max_iters=25,
            service_toolkit=service_toolkit,
        )
        return agent
