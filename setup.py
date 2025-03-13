"""
Setup script for Re-Movery
"""
from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="movery",
    version="0.1.0",
    author="heyangxu",
    author_email="",
    description="A tool for discovering modified vulnerable code clones",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/heyangxu/Re-movery",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.7",
    install_requires=[
        "pytest>=7.3.1",
        "coverage>=7.2.7",
        "jinja2>=3.0.0",
        "plotly>=5.0.0",
        "pandas>=1.3.0",
        "psutil>=5.8.0",
        "tqdm>=4.61.0",
        "colorama>=0.4.4",
        "requests>=2.26.0",
        "beautifulsoup4>=4.9.3",
        "lxml>=4.6.3",
        "pygments>=2.9.0",
        "typing-extensions>=3.10.0",
        "dataclasses>=0.8;python_version<'3.7'",
    ],
    entry_points={
        "console_scripts": [
            "movery=movery.main:main",
        ],
    },
    package_data={
        "movery": [
            "templates/*.html",
            "config/*.json",
        ],
    },
    include_package_data=True,
    zip_safe=False,
) 