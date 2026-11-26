from flask import request


def handler():
    # The fixture lacked an eval() sink; this seed gives the Python eval rule a
    # real line to match. The expression comes straight from the request.
    return eval(request.args.get("expr"))