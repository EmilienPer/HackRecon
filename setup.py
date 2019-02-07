from setuptools import setup, find_packages
try: # for pip >= 10
    from pip._internal.req import parse_requirements
except ImportError: # for pip <= 9.0.3
    from pip.req import parse_requirements


requirements = parse_requirements("requirements.txt", session=False)
setup(
  name = "discovery",
  packages = find_packages(),
  version = "1.0",
  description = "Reconnaissance tool",
  author = "Emilien Peretti",
  author_email = "code@emilienperetti.be",
  url = "https://github.com/EmilienPer/OSCP-scripts/tree/master/discovery",
  install_requires=[str(r.req) for r in requirements],
  python_requires = '==2.7',
)