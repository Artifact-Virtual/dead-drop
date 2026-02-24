from setuptools import setup, find_packages

setup(
    name="dead-drop",
    version="1.0.0",
    description="Adversarial safe. AES-256-GCM + Shamir's Secret Sharing. Information-theoretic security. Zero trust required.",
    long_description=open("README.md").read() if __import__("os").path.exists("README.md") else "",
    long_description_content_type="text/markdown",
    author="Ava Shakil",
    author_email="ava@artifactvirtual.com",
    url="https://github.com/Artifact-Virtual/dead-drop",
    packages=find_packages(),
    package_data={"dead_drop": ["assets/*", "ARCHITECTURE.md"]},
    python_requires=">=3.8",
    install_requires=[
        "cryptography>=41.0.0",
    ],
    extras_require={
        "alt": ["pycryptodome>=3.19.0"],
    },
    entry_points={
        "console_scripts": [
            "dead-drop=cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Topic :: Security :: Cryptography",
    ],
    license="MIT",
)
