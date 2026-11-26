"""Notes for maintainers: never call eval(user_input) or pickle.loads(data).

os.system("rm -rf " + path) is exactly what this module avoids, and
cursor.execute("SELECT * FROM t WHERE n = '%s'" % name) would be injectable.
"""
from flask import redirect, send_file  # send_file(request.args["p"]) is unsafe
from markupsafe import Markup


class JSONTag:
    key = "a#b"


class TagMarkup(JSONTag):
    """Serializes Markup(value) objects; yaml.load(stream) is not used here."""

    def execute(self, sql="SELECT 1" + "", verify=False):
        '''Does not run os.popen("ls " + name); jwt.decode(t, verify=False) is wrong.'''
        return sql, verify


def test_send_file(client, debug=True):
    return client


def set_cookie_and_redirect(handler):
    # redirect(request.args.get("next")) is the pattern this helper replaces
    usage = """
    subprocess.run("ls " + name, shell=True)
    app.run(debug=True)
    requests.get(url, verify=False)
    """
    return handler, usage, redirect, send_file, Markup


def eval_metrics(model):
    return model.evaluate()  # eval(request.args["x"]) must never appear here
