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

import unittest

class TEST(unittest.TestCase):
    def test_validate(self):
        self.assertTrue(validate(1, int))
        self.assertTrue(validate("A", str))
        self.assertTrue(validate([1, 2], list))
        self.assertTrue(validate({"a": "b"}, dict))

        self.assertFalse(validate(1, str))
        self.assertFalse(validate("A", int))
        self.assertFalse(validate([1, 2], dict))
        self.assertFalse(validate({"a": "b"}, list))

    def test_check(self):
        tmp = {
            "A": 1
        }
        self.assertTrue(check(tmp, "A", int))
        self.assertFalse(check(tmp, "B", int))
        self.assertFalse(check(tmp, "A", str))
