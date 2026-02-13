#!/usr/bin/env python
"""Run both SSH and Apache log analyses"""

import subprocess
import sys

print("=" * 70)
print("SSH LOG ANALYSIS - Detecting Brute Force Attacks".center(70))
print("=" * 70)
subprocess.run([sys.executable, "analyzer.py", "ssh", "samples/ssh_auth.log"])

print("\n" + "=" * 70)
print("APACHE LOG ANALYSIS - Detecting Web Scanning".center(70))
print("=" * 70)
subprocess.run([sys.executable, "analyzer.py", "apache", "samples/apache_access.log"])
