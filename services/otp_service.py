import random


def generate_otp():
    return str(random.randint(100000, 999999))


def verify_otp(input_otp, stored_otp):
    return str(input_otp) == str(stored_otp)