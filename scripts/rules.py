#!/usr/bin/env python3
"""Insert/remove only our block in the filter table; never depend on comments."""
import re
import sys
from pathlib import Path

START = '# === UFW-ANTISCAN START ==='
END = '# === UFW-ANTISCAN END ==='

def remove(text):
    if text.count(START) != text.count(END) or text.count(START) > 1:
        raise ValueError('Malformed or duplicate AntiScan markers')
    if START in text and text.index(START) > text.index(END):
        raise ValueError('Reversed AntiScan markers')
    return re.sub(re.escape(START) + r'.*?' + re.escape(END) + r'\n?', '', text, flags=re.S)

def inject(text, rules, family):
    if family not in ('4', '6'):
        raise ValueError('Invalid address family')
    text = remove(text)
    lines = text.splitlines(keepends=True)
    tables = [i for i, line in enumerate(lines) if line.strip() == '*filter']
    if len(tables) != 1:
        raise ValueError('Expected exactly one filter table')
    start = tables[0]
    end = next((i for i in range(start + 1, len(lines)) if lines[i].strip() == 'COMMIT'), None)
    if end is None or any(line.lstrip().startswith('*') for line in lines[start+1:end]):
        raise ValueError('Missing filter COMMIT')
    chain = 'ufw6-before-input' if family == '6' else 'ufw-before-input'
    if not any(line.startswith(':' + chain + ' ') for line in lines[start:end]):
        raise ValueError('Missing UFW input chain')
    # Before the first rule, after all chain declarations. The private chain's
    # RETURN resumes ufw-before-input, including its normal stateful handling.
    index = next((i for i in range(start + 1, end) if lines[i].lstrip().startswith('-')), end)
    lines.insert(index, rules.strip() + '\n')
    return ''.join(lines)

if __name__ == '__main__':
    path = Path(sys.argv[2])
    text = path.read_text()
    output = remove(text) if sys.argv[1] == 'remove' else inject(text, Path(sys.argv[3]).read_text(), sys.argv[4])
    path.write_text(output)
