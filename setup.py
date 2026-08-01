"""Compatibility metadata for legacy pip/setuptools frontends.

Modern installers read pyproject.toml. Keep the values here in sync so older
platform Python installations do not silently build an empty UNKNOWN wheel.
"""

from pathlib import Path

from setuptools import setup


README = Path(__file__).with_name("README.md").read_text(encoding="utf-8")


setup(
    name="agentsim",
    version="0.1.0",
    description="Defensive simulation of autonomous-agent command patterns",
    long_description=README,
    long_description_content_type="text/markdown",
    python_requires=">=3.9",
    license="MIT",
    py_modules=["core", "tactics", "web_ui"],
    install_requires=["Flask>=3.1,<4.0"],
    entry_points={
        "console_scripts": [
            "agentsim=core:main",
            "agentsim-web=web_ui:main",
        ]
    },
)
