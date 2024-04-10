# In patterns.py or a new file, context_patterns.py

CONTEXT_KEYWORDS = {
    'Personal Identification': {
        'keywords': ['social insurance number', 'sin', 'social security number', 'ssn', 'national insurance', 'nin'],
        'distance': 20,  # The maximum distance (in characters) to look for keywords from the matched pattern
    },
    # Define other categories as necessary
}
