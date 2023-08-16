def validate(val, type_class):
    if str(type(val)) == str(type_class):
        return True
    else:
        return False

def check(data: dict, key: str, type_class):
    if key in data and validate(data[key], type_class):
        return True
    else:
        return False
