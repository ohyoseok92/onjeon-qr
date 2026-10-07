import sqlite3

from scripts.prepare_demo import main


def test_persistent_browser_demo(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("ONJEON_ADMIN_TOKEN", "d" * 40)
    monkeypatch.setenv("ONJEON_DATABASE_PATH", str(tmp_path / "demo.sqlite3"))
    monkeypatch.setenv("ONJEON_KEY_DIRECTORY", str(tmp_path / "keys"))
    main()
    output = capsys.readouterr().out
    assert "기관 ID: demo-" in output
    assert len(list((tmp_path / "demo-output").glob("*.png"))) == 1
    with sqlite3.connect(tmp_path / "demo.sqlite3") as db:
        assert db.execute("SELECT count(*) FROM issued_qrs").fetchone()[0] == 1
