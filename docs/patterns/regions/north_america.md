# Patterns: North America

## North America - United States

| Pattern Name | Regex |
|---|---|
| USA SSN | `\b\d{3}[-.\s/\\_\u2013\u2014\u00a0]?\d{2}[-.\s/\\_\u2013\u2014\u00a0]?\d{4}\b` |
| USA ITIN | `\b9\d{2}[-.\s/\\_\u2013\u2014\u00a0]?\d{2}[-.\s/\\_\u2013\u2014\u00a0]?\d{4}\b` |
| USA EIN | `\b\d{2}[-.\s/\\_\u2013\u2014\u00a0]?\d{7}\b` |
| USA Passport | `\b\d{9}\b` |
| USA Passport Card | `\bC\d{8}\b` |
| USA Routing Number | `\b\d{9}\b` |
| US DEA Number | `\b[A-Z]{2}\d{7}\b` |
| US NPI | `\b[12]\d{9}\b` |
| US MBI | `\b[1-9][A-CEGHJ-NP-RT-Y](?:[0-9]\|[A-CEGHJ-NP-RT-Y])[0-9][-.\s/\\_\u2013\u2014\u00a0]?[A-CEGHJ-NP-RT-Y](?:[0-9]\|[A-CEGHJ-NP-RT-Y])[0-9][-.\s/\\_\u2013\u2014\u00a0]?[A-CEGHJ-NP-RT-Y]{2}[0-9]{2}\b` |
| US DoD ID | `\b\d{10}\b` |
| US Known Traveler Number | `\b\d{9}\b` |
| US Phone Number | `(?<!\d)(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}(?!\d)` |
| Alabama DL | `\b\d{7}\b` |
| Alaska DL | `\b\d{7}\b` |
| Arizona DL | `\b(?:[A-Z]\d{8}\|\d{9})\b` |
| Arkansas DL | `\b\d{8,9}\b` |
| California DL | `\b[A-Z]\d{7}\b` |
| Colorado DL | `\b(?:\d{9}\|[A-Z]\d{3,6})\b` |
| Connecticut DL | `\b\d{9}\b` |
| Delaware DL | `\b\d{1,7}\b` |
| DC DL | `\b(?:\d{7}\|\d{9})\b` |
| Florida DL | `\b[A-Z]\d{12}\b` |
| Georgia DL | `\b\d{7,9}\b` |
| Hawaii DL | `\b(?:[A-Z]\d{8}\|\d{9})\b` |
| Idaho DL | `\b[A-Z]{2}\d{6}[A-Z]\b` |
| Illinois DL | `\b[A-Z]\d{11}\b` |
| Indiana DL | `\b(?:\d{10}\|[A-Z]\d{9})\b` |
| Iowa DL | `\b\d{3}[A-Z]{2}\d{4}\b` |
| Kansas DL | `\b(?:[A-Z]\d{8}\|[A-Z]{2}\d{7}\|\d{9})\b` |
| Kentucky DL | `\b[A-Z]\d{8}\b` |
| Louisiana DL | `\b\d{9}\b` |
| Maine DL | `\b\d{7}[A-Z]?\b` |
| Maryland DL | `\b[A-Z]\d{12}\b` |
| Massachusetts DL | `\b(?:[A-Z]\d{8}\|\d{9})\b` |
| Michigan DL | `\b[A-Z]\d{12}\b` |
| Minnesota DL | `\b[A-Z]\d{12}\b` |
| Mississippi DL | `\b\d{9}\b` |
| Missouri DL | `\b(?:[A-Z]\d{5,9}\|\d{9})\b` |
| Montana DL | `\b(?:\d{13}\|\d{9})\b` |
| Nebraska DL | `\b[A-Z]\d{8}\b` |
| Nevada DL | `\b(?:\d{10}\|\d{12})\b` |
| New Hampshire DL | `\b\d{2}[A-Z]{3}\d{5}\b` |
| New Jersey DL | `\b[A-Z]\d{14}\b` |
| New Mexico DL | `\b\d{9}\b` |
| New York DL | `\b\d{9}\b` |
| North Carolina DL | `\b\d{1,12}\b` |
| North Dakota DL | `\b(?:[A-Z]{3}\d{6}\|\d{9})\b` |
| Ohio DL | `\b[A-Z]{2}\d{6}\b` |
| Oklahoma DL | `\b(?:[A-Z]\d{9}\|\d{9})\b` |
| Oregon DL | `\b\d{1,9}\b` |
| Pennsylvania DL | `\b\d{8}\b` |
| Rhode Island DL | `\b(?:\d{7}\|[A-Z]\d{6})\b` |
| South Carolina DL | `\b\d{5,11}\b` |
| South Dakota DL | `\b(?:\d{8,10}\|\d{12})\b` |
| Tennessee DL | `\b\d{7,9}\b` |
| Texas DL | `\b\d{8}\b` |
| Utah DL | `\b\d{4,10}\b` |
| Vermont DL | `\b(?:\d{8}\|\d{7}[A-Z])\b` |
| Virginia DL | `\b(?:[A-Z]\d{8,11}\|\d{9})\b` |
| Washington DL | `\b[A-Z]{1,7}[A-Z0-9*]{5,11}\b` |
| West Virginia DL | `\b(?:\d{7}\|[A-Z]\d{6})\b` |
| Wisconsin DL | `\b[A-Z]\d{13}\b` |
| Wyoming DL | `\b\d{9,10}\b` |

## North America - US Generic DL

| Pattern Name | Regex |
|---|---|
| Generic US DL | `\b[A-Z]{1,2}\d{4,14}\b` |

## North America - Canada

| Pattern Name | Regex |
|---|---|
| Canada SIN | `\b\d{3}[-.\s/\\_\u2013\u2014\u00a0]?\d{3}[-.\s/\\_\u2013\u2014\u00a0]?\d{3}\b` |
| Canada BN | `\b\d{9}[A-Z]{2}\d{4}\b` |
| Canada Passport | `\b[A-Z]{2}\d{6}\b` |
| Canada Bank Code | `\b\d{5}[-.\s/\\_\u2013\u2014\u00a0]?\d{3}\b` |
| Canada PR Card | `\b[A-Z]{2}\d{7,10}\b` |
| Canada NEXUS | `\b\d{9}\b` |
| Ontario DL | `\b[A-Z]\d{4}[-.\s/\\_\u2013\u2014\u00a0]?\d{5}[-.\s/\\_\u2013\u2014\u00a0]?\d{5}\b` |
| Ontario HC | `\b\d{10}(?:\s?[A-Z]{2})?\b` |
| Quebec DL | `\b[A-Z]\d{4}[-.\s/\\_\u2013\u2014\u00a0]?\d{6}[-.\s/\\_\u2013\u2014\u00a0]?\d{2}\b` |
| Quebec HC | `\b[A-Z]{4}\d{8}\b` |
| British Columbia DL | `\b\d{7}\b` |
| BC HC | `\b9\d{9}\b` |
| Alberta DL | `\b\d{6,9}\b` |
| Alberta HC | `\b\d{9}\b` |
| Saskatchewan DL | `\b\d{8}\b` |
| Saskatchewan HC | `\b\d{9}\b` |
| Manitoba DL | `\b[A-Z]{6}\d{6}\b` |
| Manitoba HC | `\b\d{9}\b` |
| New Brunswick DL | `\b\d{5,7}\b` |
| New Brunswick HC | `\b\d{9}\b` |
| Nova Scotia DL | `\b[A-Z]{5}\d{9}\b` |
| Nova Scotia HC | `\b\d{10}\b` |
| PEI DL | `\b\d{1,6}\b` |
| PEI HC | `\b\d{8}\b` |
| Newfoundland DL | `\b[A-Z]\d{9,10}\b` |
| Newfoundland HC | `\b\d{12}\b` |
| Yukon DL | `\b\d{6}\b` |
| NWT DL | `\b\d{6}\b` |
| Nunavut DL | `\b\d{6}\b` |

## North America - Mexico

| Pattern Name | Regex |
|---|---|
| Mexico CURP | `\b[A-Z]{4}\d{6}[HM][A-Z]{5}[A-Z0-9]\d\b` |
| Mexico RFC | `\b[A-Z&]{3,4}\d{6}[A-Z0-9]{3}\b` |
| Mexico Clave Elector | `\b[A-Z]{6}\d{8}[HM]\d{3}\b` |
| Mexico INE CIC | `\b\d{9}\b` |
| Mexico INE OCR | `\b\d{13}\b` |
| Mexico Passport | `\b[A-Z]\d{8}\b` |
| Mexico NSS | `\b\d{11}\b` |
