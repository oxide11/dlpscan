from setuptools import setup, find_packages

setup(
    name='dlpscan',
    version='0.3.0',
    author='Moussa Noun',
    author_email='moussa@polygoncyber.com',
    packages=find_packages(),
    install_requires=[
        # List your project's dependencies here.
        # For example: 'requests>=2.25.1'
    ],
    description='A tool for scanning and redacting sensitive information.',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
)
