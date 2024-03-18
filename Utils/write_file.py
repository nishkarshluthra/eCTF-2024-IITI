import os
import argparse

def write_file(file_path, data):
    with open(file_path, 'w') as file:
        for line in data:
            file.write(line)
            
argparser = argparse.ArgumentParser()
argparser.add_argument('file_path', type=str, help='File path')
argparser.add_argument('data', type=list, help='Data')

args = argparser.parse_args()

write_file(args.file_path, args.data)