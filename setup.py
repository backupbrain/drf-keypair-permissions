import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="drf-cavage",
    version="0.0.1",
    author="Adonis Gaitatzis",
    author_email="backupbrain@gmail.com",
    description="Crypto Keypair Authorization for Django Rest Framework",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/backupbrain/drf-cavage",
    packages=setuptools.find_packages(),
    install_requires=[
        'pycryptodome',
        'fastecdsa',
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 2.7",
        "Framework :: Django :: 2.0",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: OS Independent",
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",

    ],
    python_requires='>=2.7',
)
