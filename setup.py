"""
Setup script for PyFRC2G
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="pyfrc2g",
    version="2.0.0",
    author="PyFRC2G Contributors",
    description="Unified Firewall Rules to Graph Converter for pfSense and OPNSense",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/PyFRC2G",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: System Administrators",
        "Topic :: System :: Networking :: Firewalls",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.7",
    install_requires=[
        "requests>=2.25.0",
        "graphviz>=0.16",
        "reportlab>=3.6.0",
    ],
    entry_points={
        "console_scripts": [
            "pyfrc2g=pyfrc2g.main:main",
        ],
    },
)

