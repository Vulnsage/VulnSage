from abc import abstractmethod

from agentscope.agents import ReActAgent


class VulnSageReactAgent(ReActAgent):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    @classmethod
    @abstractmethod
    def create(cls, sys_prompt):
        raise NotImplementedError("VulnSageReactAgent is not implemented")
