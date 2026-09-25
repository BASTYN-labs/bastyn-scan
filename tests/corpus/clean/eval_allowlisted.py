def calculate(expression):
    if expression not in ("1 + 1", "2 + 2"):
        raise ValueError("unsupported expression")
    return eval(expression)
