class VulnTypeNotSupported(Exception):
    def __init__(self, vuln_type):
        self.vuln_type = vuln_type

    def __str__(self):
        return f"VulnTypeNotSupported: {self.vuln_type}"


class GeneralVulnTypeNotSupported(Exception):
    def __init__(self, vuln_type):
        self.vuln_type = vuln_type

    def __str__(self):
        return f"GeneralVulnTypeNotSupported: {self.vuln_type}"


class LangaugeNotSupported(Exception):
    def __init__(self, language):
        self.language = language

    def __str__(self):
        return f"LangaugeNotSupported: {self.language}"


class TaskIdNotFoundError(Exception):
    def __init__(self, task_id):
        self.task_id = task_id

    def __str__(self):
        return f"TaskIdNotFound: {self.task_id}"
