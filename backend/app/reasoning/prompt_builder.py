"""
Dynamic prompt construction using Jinja2 templates.
"""
from __future__ import annotations
from pathlib import Path
from jinja2 import Environment, FileSystemLoader

PROMPTS_DIR = Path(__file__).parent.parent.parent / "prompts"


class PromptBuilder:
    def __init__(self) -> None:
        self._env = Environment(
            loader=FileSystemLoader(str(PROMPTS_DIR)),
            autoescape=False,
        )

    def render(self, template_name: str, **kwargs: object) -> str:
        template = self._env.get_template(template_name)
        return template.render(**kwargs)
