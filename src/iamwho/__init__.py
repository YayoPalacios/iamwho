from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("iamwho")
except PackageNotFoundError:
    __version__ = "dev"
