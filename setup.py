"""Compatibility metadata for legacy pip/setuptools frontends.

Modern installers read pyproject.toml. Keep the values here in sync so older
platform Python installations do not silently build an empty UNKNOWN wheel.
"""

from pathlib import Path

from setuptools import find_packages, setup


README = Path(__file__).with_name("README.md").read_text(encoding="utf-8")


setup(
    name="agentsim",
    version="1.2.0",
    description="Detection-first adversary emulation for endpoints, cloud, and agentic AI",
    url="https://github.com/hellnbak/AgentSim",
    project_urls={
        "Repository": "https://github.com/hellnbak/AgentSim.git",
        "Issues": "https://github.com/hellnbak/AgentSim/issues",
        "Changelog": "https://github.com/hellnbak/AgentSim/blob/main/CHANGELOG.md",
    },
    long_description=README,
    long_description_content_type="text/markdown",
    python_requires=">=3.9",
    license="MIT",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3 :: Only",
        "Operating System :: OS Independent",
        "Topic :: Security",
    ],
    py_modules=["core", "mcp_lab", "scenarios", "tactics", "web_ui"],
    packages=find_packages(include=["agentsim*", "agentsim_scenarios*"]),
    package_data={
        "agentsim_scenarios.packs": ["*.json"],
        "agentsim.content.packs": ["*.json"],
        "agentsim.content.campaigns": ["*.json"],
        "agentsim.content.catalogs": ["*.json"],
        "agentsim.content": ["trusted_keys.json"],
    },
    data_files=[
        (
            "share/agentsim/schemas",
            [
                "schemas/action-event-v3.schema.json",
                "schemas/ability-pack.schema.json",
                "schemas/authorization-manifest.schema.json",
                "schemas/campaign-pack.schema.json",
                "schemas/command-catalog.schema.json",
                "schemas/agent-event.schema.json",
                "schemas/scenario-pack.schema.json",
                "schemas/normalized-event.schema.json",
                "schemas/detection-rule.schema.json",
                "schemas/external-plan.schema.json",
                "schemas/agent-trace-event.schema.json",
                "schemas/live-query-plan.schema.json",
                "schemas/reference-lab-result.schema.json",
            ],
        )
    ],
    install_requires=["Flask>=3.1,<4.0"],
    entry_points={
        "console_scripts": [
            "agentsim=agentsim.cli:main",
            "agentsim-web=agentsim.web.app:main",
        ]
    },
)
