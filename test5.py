from faker import Faker
import re

# Initialize Faker instance
faker = Faker()

# Example text containing sensitive information
text = """
My credit card number is 1234-5678-9012-3456 and my SIN is 123-456-789.
"""

print(faker.name())