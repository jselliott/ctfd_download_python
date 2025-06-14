from setuptools import setup, find_packages

setup(
    name="ctfd_downloader",
    version="1.0.1",
    packages=find_packages(),
    install_requires = [
    "requests>=2.32.0",
    "slugify>=0.0.1",
    "tqdm>=4.66.3"
    ],
    author="Jacob Elliott",
    author_email="coachelliott@uscybergames.org",
    description="A tool to download challenges, files, and metadata from a CTFd instance and output them into an organized directory.",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
    entry_points={
        'console_scripts': [
            'ctfd-downloader=ctfd_downloader.main:main',
            'ctfd-downloader-format=ctfd_downloader.format:main'
        ],
    },
)
