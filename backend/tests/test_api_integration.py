import pytest
import io
import zipfile
from fastapi.testclient import TestClient
from keynova.main import app

client = TestClient(app, raise_server_exceptions=True)

def test_health_endpoint():
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "healthy"
    assert data["service"] == "Keynova PQC Engine"
    assert "database" in data

def test_create_and_get_project():
    # 1. Create Project
    resp = client.post("/api/v1/projects", json={
        "name": "Payment Gateway Service",
        "repository_url": "https://github.com/example/payment-gateway.git"
    })
    assert resp.status_code == 201, resp.text
    project_data = resp.json()
    assert project_data["name"] == "Payment Gateway Service"
    project_id = project_data["id"]

    # 2. Get Project by ID
    resp_get = client.get(f"/api/v1/projects/{project_id}")
    assert resp_get.status_code == 200
    assert resp_get.json()["id"] == project_id

    # 3. List Projects
    resp_list = client.get("/api/v1/projects")
    assert resp_list.status_code == 200
    projects = resp_list.json()
    assert any(p["id"] == project_id for p in projects)

    # 4. List Scans for Project
    resp_scans = client.get(f"/api/v1/projects/{project_id}/scans")
    assert resp_scans.status_code == 200
    assert isinstance(resp_scans.json(), list)

def test_project_not_found():
    resp = client.get("/api/v1/projects/nonexistent-uuid")
    assert resp.status_code == 404

def test_upload_archive_and_scan():
    # 1. Create a Project
    resp = client.post("/api/v1/projects", json={"name": "Scanner Test Project"})
    assert resp.status_code == 201
    project_id = resp.json()["id"]

    # 2. Build in-memory ZIP with Python code and manifest
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w") as zf:
        code = """
from cryptography.hazmat.primitives.asymmetric import rsa
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
"""
        zf.writestr("app/crypto.py", code)
        zf.writestr("requirements.txt", "pycryptodome==3.10.1\n")

    zip_bytes = zip_buffer.getvalue()

    # 3. Upload ZIP
    files = {"file": ("test_code.zip", zip_bytes, "application/zip")}
    upload_resp = client.post(f"/api/v1/projects/{project_id}/upload", files=files)
    assert upload_resp.status_code == 202, upload_resp.text
    scan_info = upload_resp.json()
    scan_id = scan_info["scan_id"]
    assert scan_info["status"] == "completed"
    assert scan_info["extracted_files"] == 2

    # 4. Fetch Scan Status
    scan_resp = client.get(f"/api/v1/scans/{scan_id}")
    assert scan_resp.status_code == 200
    scan_data = scan_resp.json()
    assert scan_data["status"] == "completed"
    assert scan_data["total_files"] == 2
    assert scan_data["scanned_files"] == 2
    assert scan_data["severity_counts"]["critical"] >= 1
    assert scan_data["hndl_count"] >= 1

    # 5. Fetch Findings
    findings_resp = client.get(f"/api/v1/scans/{scan_id}/findings")
    assert findings_resp.status_code == 200
    findings_data = findings_resp.json()
    assert findings_data["total"] >= 2
    assert any(f["algorithm"] == "RSA" for f in findings_data["items"])

    # 6. Fetch Graph
    graph_resp = client.get(f"/api/v1/graph/{scan_id}")
    assert graph_resp.status_code == 200
    graph_data = graph_resp.json()
    assert len(graph_data["nodes"]) > 0
    assert len(graph_data["edges"]) > 0

def test_scan_not_found():
    resp = client.get("/api/v1/scans/nonexistent-scan-id")
    assert resp.status_code == 404

def test_findings_not_found():
    resp = client.get("/api/v1/scans/nonexistent-scan-id/findings")
    assert resp.status_code == 404

def test_graph_not_found():
    resp = client.get("/api/v1/graph/nonexistent-scan-id")
    assert resp.status_code == 404
