import requests

BASE_URL = "http://localhost:8080/api/interface"


def test_create_interface():
    """Test creating an interface (positive scenario)."""
    resp = requests.post(f"{BASE_URL}/create")
    assert resp.status_code == 200
    assert resp.json().get("status") == "success"

def test_get_status():
    """Test getting interface status (positive scenario, snapshot)."""
    resp = requests.get(f"{BASE_URL}/status")
    assert resp.status_code == 200
    data = resp.json()
    # Snapshot: check for expected keys
    expected_keys = {"address", "flags", "hardware_addr", "index", "mtu", "name", "netmask", "up"}
    assert expected_keys.issubset(data.keys())

def test_start_interface():
    """Test starting packet processing (positive scenario)."""
    resp = requests.post(f"{BASE_URL}/start")
    assert resp.status_code == 200
    assert resp.json().get("status") == "success"

def test_stop_interface():
    """Test stopping packet processing (positive scenario)."""
    resp = requests.post(f"{BASE_URL}/stop")
    assert resp.status_code == 200
    assert resp.json().get("status") == "success"

def test_delete_interface():
    """Test deleting an existing interface (positive scenario)."""
    resp = requests.delete(f"{BASE_URL}/delete")
    assert resp.status_code == 200
    assert resp.json().get("status") == "success" 