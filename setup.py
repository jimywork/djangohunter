from setuptools import setup

REQUIREMENTS = [
    'shodan',
    'beautifulsoup4',
    'requests',
    'click',
    'pyfiglet'
]

REPO_URL = 'https://github.com/BoxingOctopus/djangohunter'
VERSION = 0.5

setup(
    name='djangohunter',
    packages=['djangohunter', 'djangohunter.utils'],
    scripts=['djangohunter/djangohunter'],
    description='Tool designed to help identify incorrectly configured Django ' + 
                'applications that are exposing sensitive information.',
    url=REPO_URL,
    version=VERSION,
    download_url=F'{REPO_URL}/archive/0.5.0.tar.gz',
    python_requires='>=3.0',
    install_requires=REQUIREMENTS
)