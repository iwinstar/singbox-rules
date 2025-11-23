#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
import json

def log(msg: str):
    if msg.startswith('Error'):
        msg = msg.replace('Error', '\x1b[31mError\x1b[0m')
    print(msg)

def get_path(path: str = None):
    return (
        os.getcwd()
        if path is None or len(path) == 0
        else os.path.abspath(path)
    )

def assemble_rules(src_file: str):
    if not os.path.isfile(src_file):
        log(f"Error: not file {src_file}")
        return None

    if "_ip_" in src_file:
        rule_key = "ip_cidr"
    else:
        rule_key = "domain"

    content = {
        "version": 3, 
        "rules": [{
            "ip_cidr": [],
            "domain": [],
            "domain_regex": []
        }]
    }

    with open(src_file, "r") as f:
        for line in f.read().splitlines():
            if "_domain_list.txt" in src_file and ":" in line:
                splits = line.split(":")
                mark = splits[0]
                line = splits[1]
                
                if mark == "regexp":
                    rule_key = "domain_regex"
                else:
                    rule_key = "domain"

            content['rules'][0][rule_key].append(line)

    return content


def convert_rules(src_path: str, target_path: str):
    log(f"Processing: {src_path}")

    if not os.path.exists(src_path):
        log(f"Error: {src_path} is not exists.")
        return False

    if os.path.isdir(src_path):
        for file in os.listdir(src_path):
            if "_domain_list.txt" in file or "_ip_list.txt" in file:
                src_file = os.path.join(src_path, file)
                convert_rules(src_file, target_path)
            else:
                log(f"ignore: {file}")
        return
    
    content = assemble_rules(src_path)
    if content is None:
        return False

    splits = os.path.splitext(src_path)
    out_file = os.path.join(target_path, os.path.basename(splits[0]) + ".json")
    json_str = json.dumps(content, indent=4)

    with open(out_file, "w") as json_file:
        json_file.truncate()
        json_file.write(json_str)


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(f"Usage: python {sys.argv[0]} <src_path> <target_path>")

    else:
        src_path = get_path(sys.argv[1])
        target_path = get_path(sys.argv[2])
        convert_rules(src_path, target_path)
