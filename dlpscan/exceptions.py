class RedactionError(Exception):
    """Base class for exceptions in this module."""
    pass

class EmptyInputError(RedactionError):
    """Exception raised for empty or None input."""
    pass

class ShortInputError(RedactionError):
    """Exception raised for input strings with fewer than 4 printable characters."""
    pass

class InvalidCardNumberError(RedactionError):
    """Exception raised for invalid card numbers."""
    pass

class SubCategoryNotFoundError(RedactionError):
    """Exception raised when a category is not found in the patterns."""
    pass

class ExtractionError(RedactionError):
    """Raised when text extraction from a document format fails."""
    pass
