"""Regression checks for the copy-and-run README installation guide."""
from pathlib import Path


PROJECT = Path(__file__).resolve().parents[1]


def test_readme_documents_complete_wiz_install_and_run_flow():
    readme = (PROJECT / "README.md").read_text(encoding="utf-8")

    required_text = [
        "## 설치 및 실행",
        "## Installation and Running",
        "conda create --name test-idp python=3.12 --yes",
        "conda activate test-idp",
        'python -m pip install "season==2.5.2"',
        "wiz create workspace",
        "wiz project create --project=main --uri=https://github.com/ImuruKevol/test-idp.git",
        "cp project/main/config-sample/database.py project/main/config/database.py",
        "export TEST_IDP_ADMIN_PASSWORD=",
        "wiz project build --project=main",
        "wiz run --host=127.0.0.1 --port=3000",
        "http://127.0.0.1:3000/wiz",
        "## WIZ 프로젝트 구조",
        "## WIZ Project Layout",
    ]

    for text in required_text:
        assert text in readme

    assert "/root/miniconda3/envs/test-idp" not in readme
    assert "python3 -m venv" not in readme
    assert "source .venv/bin/activate" not in readme


def test_database_sample_is_ready_for_every_test_idp_package():
    sample = (PROJECT / "config-sample" / "database.py").read_text(encoding="utf-8")

    for namespace in ("base", "idpcore", "samlidp", "oidcidp"):
        assert f"{namespace} = stdClass(" in sample
        assert f'path="project/main/data/{namespace}.db"' in sample
