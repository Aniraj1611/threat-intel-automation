"""
Setup configuration for Threat Intelligence Automation Platform
"""

from setuptools import setup, find_packages

# Read README for long description
with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

# Read requirements
with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="threat-intel-automation",
    version="1.0.0",
    author="Your Name",
    author_email="your.email@university.edu",
    description="Automated Threat Intelligence Platform for Blue Team Operations",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/threat-intel-automation",
    project_urls={
        "Bug Tracker": "https://github.com/yourusername/threat-intel-automation/issues",
        "Documentation": "https://github.com/yourusername/threat-intel-automation/wiki",
        "Source Code": "https://github.com/yourusername/threat-intel-automation",
    },
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Intended Audience :: Science/Research",
        "Topic :: Security",
        "Topic :: Scientific/Engineering :: Information Analysis",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "black>=22.0.0",
            "flake8>=5.0.0",
            "mypy>=0.990",
            "isort>=5.10.0",
        ],
        "docs": [
            "sphinx>=5.0.0",
            "sphinx-rtd-theme>=1.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "threat-intel=threat_intel.cli:main",
        ],
    },
    include_package_data=True,
    keywords="threat-intelligence cybersecurity siem ioc blue-team security-automation",
)
