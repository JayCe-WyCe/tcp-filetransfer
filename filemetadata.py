# filemetadata.py
# script responsible for giving utilities for a file, for example,
# the file size, and also reading in chunks.

import os

def make_folder(path):
    os.mkdir(path)

def check_path(path):
    return os.path.exists(path)

def get_path(folders):
    return os.path.join(*folders)

def get_files(path):
    files = [f for f in os.listdir(path)
                 if os.path.isfile(os.path.join(path, f))]
    return files

def get_filesize(path):
    try:
        filesize = os.path.getsize(path)
    except:
        filesize = -1
    return filesize

def get_chunkcount(filesize, chunksize):
    chunkcount = filesize//chunksize + int(bool(filesize%chunksize))
    return chunkcount
