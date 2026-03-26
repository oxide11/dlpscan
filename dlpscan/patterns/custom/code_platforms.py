import re


CODE_PLATFORMS_PATTERNS = {
    'Code Platform Secrets': {
        'GitHub Token (Classic)': re.compile(r'\bghp_[A-Za-z0-9]{36}\b'),
        'GitHub Token (Fine-Grained)': re.compile(r'\bgithub_pat_[A-Za-z0-9_]{22,82}\b'),
        'GitHub OAuth Token': re.compile(r'\bgho_[A-Za-z0-9]{36}\b'),
        'NPM Token': re.compile(r'\bnpm_[A-Za-z0-9]{36}\b'),
        'PyPI Token': re.compile(r'\bpypi-[A-Za-z0-9_\-]{16,}\b'),
    },
}
