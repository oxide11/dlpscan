

CLASSIFICATION_LABELS_CONTEXT = {
    # ── Regulatory & Supervisory Classification ─────────────────────
    'Supervisory Information': {
        'Identifiers': {
            'Supervisory Controlled': ['supervisory', 'controlled', 'occ', 'fdic', 'federal reserve', 'regulator', 'examination'],
            'Supervisory Confidential': ['supervisory', 'confidential', 'regulator', 'examination', 'bank examination'],
            'CSI': ['confidential supervisory', 'csi', 'examination report', 'regulatory report', 'supervisory letter'],
            'Non-Public Supervisory': ['non-public', 'supervisory', 'regulatory', 'examination', 'not for release'],
            'Restricted Supervisory': ['restricted', 'supervisory', 'regulatory', 'compliance', 'enforcement'],
            'Examination Findings': ['examination', 'mra', 'mria', 'findings', 'regulatory', 'corrective action', 'consent order'],
        },
        'distance': 80,
    },
    # ── Privileged Information ──────────────────────────────────────
    'Privileged Information': {
        'Identifiers': {
            'Attorney-Client Privilege': ['attorney', 'client', 'privilege', 'legal counsel', 'law firm', 'privileged communication'],
            'Privileged and Confidential': ['privileged', 'confidential', 'legal', 'attorney', 'counsel'],
            'Work Product': ['work product', 'attorney', 'litigation', 'legal', 'prepared in anticipation'],
            'Privileged Information': ['privileged', 'legal', 'attorney', 'counsel', 'protected'],
            'Legal Privilege': ['legal', 'privilege', 'attorney', 'counsel', 'protected communication'],
            'Litigation Hold': ['litigation', 'legal hold', 'preservation', 'hold notice', 'document retention'],
            'Protected by Privilege': ['privilege', 'protected', 'attorney', 'legal', 'exempt from disclosure'],
        },
        'distance': 100,
    },
    # ── Data Classification Labels ──────────────────────────────────
    'Data Classification Labels': {
        'Identifiers': {
            'Top Secret': ['classified', 'top secret', 'ts', 'sci', 'national security', 'clearance'],
            'Secret Classification': ['classified', 'secret', 'national security', 'clearance', 'noforn'],
            'Confidential Classification': ['classified', 'confidential', 'national security', 'government'],
            'FOUO': ['official use', 'fouo', 'government', 'not for public release'],
            'CUI': ['cui', 'controlled unclassified', 'sensitive information', 'marking'],
            'SBU': ['sensitive', 'unclassified', 'sbu', 'government'],
            'LES': ['law enforcement', 'sensitive', 'les', 'police', 'investigation'],
            'NOFORN': ['noforn', 'foreign nationals', 'not releasable', 'classification'],
        },
        'distance': 100,
    },
    # ── Corporate/Enterprise Classification ─────────────────────────
    'Corporate Classification': {
        'Identifiers': {
            'Internal Only': ['internal', 'company', 'employees only', 'staff only', 'not for external'],
            'Restricted': ['restricted', 'limited distribution', 'access controlled', 'need to know'],
            'Corporate Confidential': ['confidential', 'company', 'corporate', 'business', 'proprietary'],
            'Highly Confidential': ['highly confidential', 'sensitive', 'restricted', 'executive only'],
            'Do Not Distribute': ['distribute', 'distribution', 'circulation', 'forward', 'share'],
            'Need to Know': ['need to know', 'restricted access', 'limited distribution', 'authorized personnel'],
            'Eyes Only': ['eyes only', 'recipient only', 'personal', 'addressee only'],
            'Proprietary': ['proprietary', 'trade secret', 'intellectual property', 'confidential business'],
            'Embargoed': ['embargo', 'embargoed', 'hold until', 'not for release', 'publication date'],
        },
        'distance': 80,
    },
    # ── Financial Regulatory Labels ─────────────────────────────────
    'Financial Regulatory Labels': {
        'Identifiers': {
            'MNPI': ['mnpi', 'material', 'non-public', 'insider', 'trading', 'securities'],
            'Inside Information': ['inside information', 'insider', 'material', 'non-public', 'trading restriction'],
            'Pre-Decisional': ['pre-decisional', 'draft', 'deliberative', 'not final', 'preliminary'],
            'Draft Not for Circulation': ['draft', 'circulation', 'preliminary', 'not final', 'review only'],
            'Market Sensitive': ['market sensitive', 'price sensitive', 'stock', 'securities', 'trading'],
            'Information Barrier': ['information barrier', 'chinese wall', 'wall crossing', 'restricted side', 'public side'],
            'Investment Restricted': ['restricted list', 'watch list', 'grey list', 'restricted securities', 'trading restriction'],
        },
        'distance': 80,
    },
    # ── Privacy & Data Protection Labels ────────────────────────────
    'Privacy Classification': {
        'Identifiers': {
            'PII Label': ['pii', 'personally identifiable', 'personal information', 'sensitive data'],
            'PHI Label': ['phi', 'protected health', 'health information', 'medical records', 'patient data'],
            'HIPAA': ['hipaa', 'health insurance portability', 'medical privacy', 'health data'],
            'GDPR Personal Data': ['gdpr', 'personal data', 'data subject', 'data protection', 'eu regulation'],
            'PCI-DSS': ['pci', 'pci-dss', 'cardholder data', 'payment card', 'card data environment'],
            'FERPA': ['ferpa', 'educational records', 'student records', 'student privacy'],
            'GLBA': ['glba', 'gramm-leach-bliley', 'financial privacy', 'consumer financial'],
            'CCPA/CPRA': ['ccpa', 'cpra', 'california consumer', 'california privacy', 'consumer rights'],
            'SOX': ['sox', 'sarbanes-oxley', 'financial reporting', 'internal controls', 'audit'],
            'NPI': ['npi', 'non-public personal', 'financial privacy', 'glba', 'consumer information'],
        },
        'distance': 80,
    },
}
