import requests
import pytest

BASE_URL = "http://localhost:8080/api/interface"


def test_double_creation():
    """Test creating the same interface twice (should error on second attempt)."""
    requests.delete(f"{BASE_URL}/delete")  # Ensure clean state
    resp1 = requests.post(f"{BASE_URL}/create")
    assert resp1.status_code == 200
    resp2 = requests.post(f"{BASE_URL}/create")
    assert resp2.status_code != 200 or resp2.json().get("status") != "created"

def test_delete_nonexistent_interface():
    """Test deleting a non-existent interface (should error)."""
    requests.delete(f"{BASE_URL}/delete")  # Ensure clean state
    resp = requests.delete(f"{BASE_URL}/delete")
    assert resp.status_code != 200

def test_operation_on_nonexistent_interface():
    """Test performing operations on a non-existent interface (should error)."""
    requests.delete(f"{BASE_URL}/delete")  # Ensure clean state
    resp = requests.post(f"{BASE_URL}/start")
    assert resp.status_code != 200
    resp = requests.post(f"{BASE_URL}/stop")
    assert resp.status_code != 200

def test_start_after_delete():
    """Test starting interface after it has been deleted (should error)."""
    requests.delete(f"{BASE_URL}/delete")
    requests.post(f"{BASE_URL}/create")
    requests.delete(f"{BASE_URL}/delete")
    resp = requests.post(f"{BASE_URL}/start")
    assert resp.status_code != 200

def test_stop_after_delete():
    """Test stopping interface after it has been deleted (should error)."""
    requests.delete(f"{BASE_URL}/delete")
    requests.post(f"{BASE_URL}/create")
    requests.delete(f"{BASE_URL}/delete")
    resp = requests.post(f"{BASE_URL}/stop")
    assert resp.status_code != 200

def test_wrong_http_method_on_create():
    """Test using GET on /create (should error)."""
    resp = requests.get(f"{BASE_URL}/create")
    assert resp.status_code >= 400

def test_wrong_http_method_on_delete():
    """Test using POST on /delete (should error)."""
    resp = requests.post(f"{BASE_URL}/delete")
    assert resp.status_code >= 400

def test_invalid_url():
    """Test using an invalid endpoint (should 404)."""
    resp = requests.post(f"{BASE_URL}/nonexistent")
    assert resp.status_code == 404 