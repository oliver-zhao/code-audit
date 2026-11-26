import ast
import importlib
import json
import subprocess

import numpy
import torch
import yaml
from django.utils.html import format_html
from django.utils.safestring import mark_safe
from flask import render_template, render_template_string
from jinja2 import Environment, Template, select_autoescape
from markupsafe import Markup, escape

PAGE = "<h1>Hello {{ name }}</h1>"


def run_tools(name, model):
    subprocess.run(["ls", "-l", name], check=True)
    subprocess.run("ls -l", shell=True, check=True)
    subprocess.check_output(["ping", "-c", "1", name])
    result = ast.literal_eval("1 + 1")
    exec("x = 1")
    model.eval()
    importlib.import_module("json")
    return result


def render(name, env, js):
    render_template(f"{js}.html", js=js)
    render_template("page.html", name=name)
    render_template_string(PAGE, name=name)
    render_template_string("<h1>Hello {{ name }}</h1>", name=name)
    env.from_string("Hello {{ name }}")
    Template("Hello {{ name }}")
    Environment(loader=None, autoescape=select_autoescape())
    mark_safe("<b>ok</b>")
    format_html("<b>{}</b>", name)
    Markup("<b>ok</b>")
    Markup("<i>%s</i>") % name
    Markup("<i>{}</i>").format(name)
    Markup(escape(name))


def load(blob, checkpoint):
    json.loads(blob)
    yaml.safe_load(blob)
    yaml.load(blob, Loader=yaml.SafeLoader)
    torch.load(checkpoint, weights_only=True)
    numpy.load(checkpoint, allow_pickle=False)
