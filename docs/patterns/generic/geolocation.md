# Patterns: Geolocation

## Geolocation

| Pattern Name | Regex |
|---|---|
| GPS Coordinates | `-?\d{1,3}\.\d{4,8},\s?-?\d{1,3}\.\d{4,8}` |
| GPS DMS | `\d{1,3}[°]\d{1,2}[\'′]\d{1,2}(?:\.\d+)?[\"″]?\s?[NSEW]` |
| Geohash | `\b(?=[0-9bcdefghjkmnpqrstuvwxyz]*\d)[0-9bcdefghjkmnpqrstuvwxyz]{7,12}\b` |
