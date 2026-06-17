"""
PhishGuard AI - Package Setup
Installs the 'phishguard' CLI command.
"""

from setuptools import setup, find_packages

with open("README.md", encoding="utf-8") as f:
    long_description = f.read()

with open("requirements.txt") as f:
    requirements = [
        line.strip() for line in f
        if line.strip() and not line.startswith("#")
    ]

setup(
    name="phishguard-ai",
    version="1.0.0",
    author="PhishGuard AI Contributors",
    description="AI-powered phishing email detection tool for security professionals",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/phishguard",
    license="MIT",
    packages=find_packages(exclude=["tests*", "docs*", "datasets*", "models*"]),
    python_requires=">=3.12",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "phishguard=cli.phishguard:cli",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Environment :: Web Environment",
        "Framework :: Flask",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Internet :: WWW/HTTP :: WSGI :: Application",
    ],
    keywords="phishing detection machine-learning email security kali-linux",
    include_package_data=True,
    package_data={
        "app": ["templates/**/*.html", "static/**/*"],
    },
)
