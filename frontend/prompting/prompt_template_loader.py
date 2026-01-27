import logging

import jinja2
from jinja2 import Environment, FileSystemLoader, Template

from common import LangaugeNotSupported
from configs import LANGUAGE_JAVA, LANGUAGE_NODEJS, VULN_SAGE_FRONTEND_ROOT_PATH, LANGUAGE_PYTHON

logger = logging.getLogger("prompting")

template_dir = VULN_SAGE_FRONTEND_ROOT_PATH / "prompting" / "prompts"
logger.info(f"template_dir: {template_dir}")
TemplateEnv = Environment(loader=FileSystemLoader(template_dir), undefined=jinja2.StrictUndefined)


def check_language(language: str):
    if language not in [LANGUAGE_NODEJS, LANGUAGE_JAVA, LANGUAGE_PYTHON]:
        logger.error(f"language {language} not supported")
        raise LangaugeNotSupported(language)


class PromptTemplateLoader:
    @staticmethod
    def get_user_template(language: str, vuln_type: str, target_template: str) -> Template:
        """
        Retrieve the user template based on the specified language, vulnerability type, and target template.

        Args:
            language (str):
                The programming language of the template (e.g., Java, Node.js).
            vuln_type (str):
                The type of vulnerability; if not "common", it will be transformed into a built-in type.
            target_template (str):
                The name of the target template to load.

        Returns:
            Template:
                The loaded Jinja2 Template object corresponding to the user template file.

        Raises:
            LangaugeNotSupported: If the provided language is not supported.
            GeneralVulnTypeNotSupported: If the provided vulnerability type is not supported.

        Template File Structure:
            The method looks up templates organized under the structure:
            `{language}/{transformed_vuln_type}/{target_template}.user.html`.
        """
        check_language(language)
        return TemplateEnv.get_or_select_template(
            f"{language}/{vuln_type}/{target_template}" + ".user.html"
        )

    @staticmethod
    def get_system_template(language: str, vuln_type: str, target_template: str) -> Template:
        """
        Retrieve the system template based on the specified language, vulnerability type, and target template.

        Args:
            language (str):
                The programming language of the template (e.g., Java, Node.js).
            vuln_type (str):
                The type of vulnerability; if not "common", it will be transformed into a built-in type.
            target_template (str):
                The name of the target template to load.

        Returns:
            Template:
                The loaded Jinja2 Template object corresponding to the system template file.

        Raises:
            LangaugeNotSupported: If the provided language is not supported.
            GeneralVulnTypeNotSupported: If the provided vulnerability type is not supported.

        Template File Structure:
            The method looks up templates organized under the structure:
            `{language}/{transformed_vuln_type}/{target_template}.system.html`.
        """
        check_language(language)
        return TemplateEnv.get_or_select_template(
            f"{language}/{vuln_type}/{target_template}" + ".system.html"
        )
