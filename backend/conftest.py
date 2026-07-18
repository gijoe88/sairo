"""Pytest configuration for the Sairo backend suite.

Imported by pytest BEFORE any test module in this directory, and therefore
before test_main.py sets DB_DIR via os.environ.setdefault and before
backend/main.py is imported and initializes its databases.

Wipes the shared scratch DB directory at the start of every session so the
non-idempotent INSERTs in test_scaling.py do not accumulate state across runs.
Without this, two test_scaling.py tests fail on the second and later pytest
invocations (UNIQUE-constraint violations / row accumulation) because
test_main.py wins the DB_DIR setdefault race (alphabetical import order) and
test_scaling.py ends up writing into the same persistent /tmp/sairo-test.

Guarded: only wipes when DB_DIR resolves to the default test path, so an
operator who exports a real DB_DIR is never affected.
"""
import os
import shutil

_TEST_DB_DIR = "/tmp/sairo-test"
if os.environ.get("DB_DIR", _TEST_DB_DIR) == _TEST_DB_DIR:
    shutil.rmtree(_TEST_DB_DIR, ignore_errors=True)
os.makedirs(_TEST_DB_DIR, exist_ok=True)
