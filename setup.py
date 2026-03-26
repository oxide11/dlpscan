from setuptools import setup, find_packages
from pathlib import Path

long_description = Path('README.md').read_text(encoding='utf-8')

setup(
    name='dlpscan',
    version='0.5.0',
    author='Moussa Noun',
    author_email='moussa@polygoncyber.com',
    packages=find_packages(),
    python_requires='>=3.8',
    install_requires=[],
    description='A tool for scanning and redacting sensitive information.',
    long_description=long_description,
    long_description_content_type='text/markdown',
    classifiers=[
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Topic :: Security',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],
    keywords='dlp data-loss-prevention sensitive-data redaction pii regex scanner',
    entry_points={
        'console_scripts': [
            'dlpscan=dlpscan.input:main',
        ],
    },
)
