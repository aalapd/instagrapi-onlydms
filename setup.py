from setuptools import find_packages, setup

long_description = """
Fast and effective Instagram Private API wrapper (public+private requests and challenge resolver).

Use the most recent version of the API from Instagram.

Features:

Basic version of Instagrapi developed by Mark Subzeroid
"""

requirements = [
    "pydantic==1.8.2",
    "pycryptodomex==3.21.0",
    "requests==2.32.3"
]

setup(
    name="instagrapi-onlydms", 
    version="0.0.1",
    author="Aalap Davjekar",
    author_email="143403577+subzeroid@users.noreply.github.com", 
    license="MIT",
    url="https://github.com/aalapd/instagrapi-onlydms",
    install_requires=requirements,
    keywords=[
        "instagram private api",
        "instagram-private-api",
        "instagram api",
        "instagram-api",
        "instagram",
        "instagram-scraper",
        "instagram-client",
    ],
    description="Fast and effective Instagram Private API wrapper (forked for only DM retrieval)",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=find_packages(),
    python_requires=">=3.9",
    include_package_data=True,
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
    ],
)
