import importlib
import marshal
import os
import pickle
import subprocess

import numpy
import torch
import yaml
from django.utils.safestring import mark_safe
from flask import render_template_string, request
from jinja2 import Environment, Template
from markupsafe import Markup


def run_tools(name, env, blob, checkpoint):
    os.popen("ls " + name)  # seed: py-command-injection
    os.popen(name)  # seed: py-os-system-api
    subprocess.check_output(f"ping -c 1 {name}", shell=True)  # seed: py-subprocess-shell
    subprocess.run("make clean all", shell=True)  # seed: py-subprocess-shell-api
    subprocess.run("convert " + name)  # seed: py-subprocess-concat
    eval(request.form["expr"])  # seed: py-eval-dynamic
    exec(request.get_json()["code"])  # seed: py-exec-dynamic
    exec(name)  # seed: py-eval-api
    importlib.import_module(name)  # seed: py-importlib-dynamic


def render(name, env):
    render_template_string("<h1>Hello %s</h1>" % name)  # seed: py-render-template-string
    Template(request.args.get("tpl"))  # seed: py-jinja-template-var
    env.from_string(name)  # seed: py-template-string-api
    Environment(loader=None, autoescape=False)  # seed: py-jinja-autoescape-false
    Environment(loader=None)  # seed: py-jinja-autoescape-missing
    mark_safe("<b>" + name + "</b>")  # seed: py-mark-safe-dynamic
    Markup(f"<i>{name}</i>")  # seed: py-markup-dynamic
    Markup(name)  # seed: py-html-safe-api


def load(blob, checkpoint):
    pickle.loads(request.get_data())  # seed: py-insecure-deserialization
    marshal.loads(blob)  # seed: py-deserialization-api
    yaml.load(blob, Loader=yaml.Loader)  # seed: py-yaml-load
    torch.load(checkpoint)  # seed: py-torch-load
    numpy.load(checkpoint, allow_pickle=True)  # seed: py-numpy-load-pickle
    yaml.unsafe_load(blob)  # seed: py-yaml-load
    unsafe_body = blob
    yaml.load(unsafe_body)  # seed: py-yaml-load
    yaml.load(blob, Loader=yaml.UnsafeLoader)  # seed: py-yaml-load
    # A command that is not a literal, run through a shell: a finding even
    # though this statement does not show where the value comes from.
    subprocess.run(checkpoint, shell=True)  # seed: py-subprocess-shell
