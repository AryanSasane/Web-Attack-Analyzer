import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from rules import sqli, xss, traversal

def test_sqli_union():
    assert sqli.detect("id=1 UNION SELECT * FROM users") != []

def test_sqli_or_bypass():
    assert sqli.detect("user=' OR '1'='1") != []

def test_sqli_clean():
    assert sqli.detect("username=alice&password=hunter2") == []

def test_xss_script():
    assert xss.detect("<script>alert(1)</script>") != []

def test_xss_onerror():
    assert xss.detect('<img src=x onerror="alert(1)">') != []

def test_xss_clean():
    assert xss.detect("search=hello+world") == []

def test_traversal_dotdot():
    assert traversal.detect("../etc/passwd") != []

def test_traversal_encoded():
    assert traversal.detect("%2e%2e%2fetc%2fpasswd") != []

def test_traversal_clean():
    assert traversal.detect("/api/v1/users/42") == []