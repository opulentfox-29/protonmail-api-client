from pathlib import Path

from setuptools import find_packages, setup

install_requires = [
    'aiohttp',
    'bcrypt',
    'PGPy',
    'playwright',
    'pycryptodome',
    'requests',
    'requests-toolbelt',
    'tqdm',
]

setup(
    name='protonmail-api-client',
    version='1.1.1',
    python_requires='>=3.9',
    description='This is not an official python ProtonMail API client. it allows you to read, send and delete messages in protonmail, as well as render a ready-made template with embedded images.',
    long_description=Path("README.md").read_text(encoding="utf-8"),
    long_description_content_type='text/markdown',
    author='opulentfox-29',
    author_email='3acqw2bx@duck.com',
    url='https://github.com/opulentfox-29/protonmail-api-client',
    install_requires=install_requires,
    keywords='protonmail api client proton proton-mail send read mail email',
    packages=find_packages(),
    include_package_data=True,
)
