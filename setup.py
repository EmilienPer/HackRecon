from setuptools import setup, find_packages
try: # for pip >= 10
    from pip._internal.req import parse_requirements
except ImportError: # for pip <= 9.0.3
    from pip.req import parse_requirements


with open("README.md", "r") as fh:
    long_description = fh.read()

requirements = parse_requirements("requirements.txt", session=False)
setup(
  name = "hackrecon",
  packages = find_packages(),
  version = "1.3",
  license = "AGPLv3",
  description = "Reconnaissance tool",
  author = "Emilien Peretti",
  author_email = "code@emilienperetti.be",
  url = "https://github.com/EmilienPer/HackRecon",
  install_requires=[str(r.req) for r in requirements],
  long_description=long_description,
  long_description_content_type="text/markdown",
  entry_points={
        'console_scripts': ['hackrecon=hackrecon.hackrecon:main_with_args'],
    }
)