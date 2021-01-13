import re
from pathlib import Path
import setuptools


def get_long_description():
    """Get README."""
    long_description = ''
    with open("README.md", "r") as fh:
        long_description = fh.read()
    return long_description


def get_version(package):
    """Get current version."""
    version = (Path("src") / package / "__version__.py").read_text()
    match = re.search("__version__ = ['\"]([^'\"]+)['\"]", version)
    assert match is not None
    return match.group(1)


setuptools.setup(
    name="drf-keypair-permissions",
    version=get_version('keypair_permissions'),
    author="Adonis Gaitatzis",
    author_email="backupbrain@gmail.com",
    packages=setuptools.find_packages("src"),
    package_dir={"": "src"},
    description="Crypto Keypair Authorization for Django Rest Framework",
    long_description=get_long_description(),
    long_description_content_type="text/markdown",
    url="https://github.com/backupbrain/drf-keypair-permissions",
    project_urls={
        "Documentation": "https://drf-keypair-permissions.readthedocs.io/"
    },
    install_requires=[
        'pycryptodome',
        'fastecdsa',
    ],
    classifiers=[
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "License :: OSI Approved :: ISC License (ISCL)",
        "Operating System :: OS Independent",
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Environment :: Web Environment",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Framework :: Django",
        "Framework :: Django :: 2.2",
        "Framework :: Django :: 3.0",

    ],
    python_requires=">=3.6",
)
