from setuptools import setup, find_packages

setup(
    name='CipherMate',
    version='1.0.0',
    packages=find_packages(),
    install_requires=[
        'click',
        'pyperclip',
        'rich',
        'pycryptodome',
        'pyfiglet'
    ],
    entry_points={
        'console_scripts': [
            'ciphermate=interface.interface:main',
        ],
    },
    author='Ameur',
    author_email='ame.4x0@example.com',
    description='A Powerful Encryption CLI Tool',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    url='https://github.com/AmeUr56/CipherMate',
)
