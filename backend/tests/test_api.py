def test_health(app_client):
    r = app_client.get("/api/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert "components" in body


def test_root(app_client):
    r = app_client.get("/")
    assert r.status_code == 200
    assert r.json()["name"] == "APEIRON"


def test_submit_rejects_non_binary(app_client):
    r = app_client.post("/api/samples", files={"file": ("note.txt", b"just text", "text/plain")})
    assert r.status_code == 415


def test_submit_rejects_empty(app_client):
    r = app_client.post(
        "/api/samples",
        files={"file": ("empty.exe", b"", "application/octet-stream")},
    )
    assert r.status_code == 400


def test_submit_and_fetch_pe(app_client, minimal_pe):
    r = app_client.post(
        "/api/samples",
        files={"file": ("sample.exe", minimal_pe, "application/octet-stream")},
    )
    assert r.status_code == 202, r.text
    data = r.json()
    sample_id = data["id"]
    assert data["status"] == "queued"
    assert len(data["sha256"]) == 64
    # The (patched) queue should have recorded the id.
    assert sample_id in app_client.enqueued

    detail = app_client.get(f"/api/samples/{sample_id}")
    assert detail.status_code == 200
    assert detail.json()["file_format"] == "PE"

    listing = app_client.get("/api/samples")
    assert listing.status_code == 200
    assert listing.json()["total"] >= 1


def test_trace_endpoint_empty(app_client, minimal_elf):
    r = app_client.post(
        "/api/samples",
        files={"file": ("x.bin", minimal_elf, "application/octet-stream")},
    )
    sample_id = r.json()["id"]
    tr = app_client.get(f"/api/samples/{sample_id}/trace")
    assert tr.status_code == 200
    assert tr.json()["total"] == 0


def test_stats_endpoint(app_client):
    r = app_client.get("/api/stats")
    assert r.status_code == 200
    assert "samples_total" in r.json()


def test_404_for_missing_sample(app_client):
    assert app_client.get("/api/samples/doesnotexist").status_code == 404
