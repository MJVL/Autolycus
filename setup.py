from setuptools import setup, find_packages


setup(
    name="Autolycus",
    author="Michael Van Leeuwen",
    url="https://github.com/MJVL/Autolycus",
    long_description=open("README.md").read(),
    python_requires=">=3.6",
    packages=find_packages(),
    install_requires = [
        "pyshark",
        "argparse",
        "colorlog",
        "fabulous"
    ],
    entry_points = {
        "console_scripts": [
            "autolycus=src.autolycus:main",
        ]
    }
)