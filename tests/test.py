from dlpscan.scanner import enhanced_scan_text as scan_text

# Define a list of test cases - each test case is a tuple containing the test string and a description
test_cases = [
    ("My SIN is 123-456-789.", "Canada SIN", False),
    ("Found SSN: 987-65-4321 in the text.", "USA SSN", False),
    ("Credit card number 4111 1111 1111 1111 is a Visa.", "Visa Credit Card", False),
    ("MasterCard number 5500 0000 0000 0004 was used.", "MasterCard Credit Card", False),
    ("Amex card: 3400 000000 00009.", "Amex Credit Card", False),
    ("Discover card number 6011 0000 0000 0004.", "Discover Credit Card", False),
    ("Driver's license in Ontario: A1234-12345-12345.", "Ontario Driver License", False),
    ("BCDL number is 1234567.", "British Columbia Driver License", False),
    ("Ontario Health Card number 1234 567 890.", "Ontario Health Card", False),
    ("Canadian Passport number AB123456.", "Canadian Passport", False),
    ("SIN: 932-123-456 valid in Canada.", "Canada SIN with dashes", False),
    ("My new SSN is 123 45 6789.", "USA SSN with spaces", False),
    ("Invalid SIN: 123456789 should not pass.", "Invalid Canada SIN", False),
    ("Visa card found: 4111111111111111.", "Visa Credit Card without spaces", False),
    ("MasterCard: 5500-0000-0000-0004 spotted.", "MasterCard Credit Card with dashes", False),
    ("American Express: 3400 000000 00009 is expired.", "Amex Credit Card with spaces", False),
    ("Discover: 6011-0000-0000-0004 rewards.", "Discover Credit Card with dashes", False),
    ("Ontario DL: B1234-12345-12345 found in records.", "Ontario Driver License variation", False),
    ("Driver License for BC: 7654321 is under review.", "British Columbia Driver License variation", False),
    ("Health Card in ON: 9876 543 210.", "Ontario Health Card with spaces", False),
    ("Passport CA: CD654321 needs renewal.", "Canadian Passport variation", False),
    ("UK NIN found: AB123456C in the document.", "UK NIN", False),
    ("NIRC Singapore: S1234567A verified.", "Singapore NIRC", False),
    ("My debit card 6011000000000004 isn't working.", "Discover Debit Card", False),
    ("Found old MC: 2221 0000 0000 0000 in the drawer.", "MasterCard Credit Card new series", False),
    ("Temporary SIN: 919-123-456 used for testing.", "Temporary Canada SIN", False),
    ("Alberta Health Card: 1234567890 is active.", "Alberta Health Card", False),
    ("PEI Driver License: 12345678 spotted during check.", "PEI Driver License", False),
    ("Nunavut DL: 1234567 has expired.", "Nunavut Driver License", False),
    ("Visa card 4111-1111-1111-1234 was declined.", "Visa Credit Card with dash separators", False),
    ("My SIN is 123 456 789.", "Canada SIN with spaces", False),
    ("SSN found: 987-65-4320 in the application.", "USA SSN", False),
    ("Credit card 5105 1051 0510 5100 is a MasterCard.", "MasterCard Credit Card", False),
    ("Driver's license from Manitoba: A123456789012.", "Manitoba Driver License", False),
    ("New Brunswick Health Card: 1234567 is valid until 2025.", "New Brunswick Health Card", False),
    ("Random text with numbers 1234-5678 should not match.", "Random text with hyphenated numbers", False),
    ("The quick brown fox jumps over 13 lazy dogs.", "Phrase with numbers", False),
    ("ISBN 978-3-16-148410-0 should not be identified as sensitive.", "ISBN format", False),
    ("Order number 6543210987 received on 2020-05-21.", "Order number with date", False),
    ("Call me at 555-2368 at 8 PM.", "Phone number with time", False),
    ("Flight AF1234 departs at 15:30.", "Flight number with time", False),
    ("Meeting ID: 456 789 1234 Passcode: 9876.", "Zoom meeting ID and passcode", False),
    ("Temperature will be between 20-25 degrees Celsius.", "Temperature range", False),
    ("The hex color for lavender is #E6E6FA.", "Hex color code", False),
    ("Error code: 500 Internal Server Error.", "HTTP error code", False),
    ("Product ID: A1B2C3D4 should be restocked.", "Product ID", False),
    ("Tracking number: 1Z 999 AA1 01 2345 6784.", "Parcel tracking number", False),
    ("License plate number ABC-1234.", "Vehicle license plate", False),
    ("IP address 192.168.1.1 should be whitelisted.", "IP address", False),
    ("Postcode: A1A 2B2 is in Canada.", "Canadian postal code", False),
    ("Bank transaction ID: 1234567890ABCDEF.", "Bank transaction ID", False),
    ("Your balance is $1234.56 as of 2024-04-01.", "Financial balance with date", False),
    ("My recipe includes 3 tsp of sugar and 2 cups of flour.", "Cooking recipe measurements", False),
    ("Room dimensions are 12x15 feet.", "Room dimensions", False),
    ("Heart rate is stable at 72 bpm.", "Heart rate in bpm", False),
    ("The train departs at platform 9¾.", "Fictional platform number", False),
    ("The rocket launch is scheduled for T-minus 10 seconds.", "Rocket launch countdown", False),
    ("Membership ID: 987654321 is due for renewal.", "Membership ID", False),
    ("Serial number: SN1234567890 for the device.", "Device serial number", False),
    ("John's SIN 123-456-789 is valid.", "Canada SIN with keyword before", True),
    ("Social Insurance Number: 987-65-4321 for auditing.", "USA SSN with keyword before", True),
    ("Visa 4111 1111 1111 1111 issued to Jane.", "Visa Credit Card with keyword before", True),
    ("Found SSN: 123 45 6789 in the application, needs verification.", "USA SSN with keyword after", True),
    ("Passport number CD654321 for Canadian citizen.", "Canadian Passport with keyword before", True),
    ("Alberta Health Card number 1234567890 is active, confirmed.", "Alberta Health Card with keyword after", True),
    ("My library card 1234 5678 9101 1121 should not match.", "Non-sensitive number with irrelevant keyword", False),
    ("Membership ID: 987654321 without context.", "Membership ID without context", False),
]
# Function to test all cases and print results
# Function to test all cases and print results, adjusted for context checking
def run_tests():
    for idx, (text, description, expects_context) in enumerate(test_cases, start=1):
        print(f"Test Case {idx}: {description}")
        try:
            findings = scan_text(text)
            context_detected = any(finding[2] for finding in findings)  # Assuming the third element indicates context
            if context_detected == expects_context:
                print(" Test passed. Context detection as expected.")
            else:
                print(" Test failed. Context detection did not match expectation.")
        except ValueError as e:
            print(f" Error: {str(e)}")
        print("---------------------------------------------")

if __name__ == "__main__":
    run_tests()
