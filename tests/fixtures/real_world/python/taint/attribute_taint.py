import os

class Config:
    pass

config = Config()
config.cmd = os.getenv("CMD")
os.system(config.cmd)
