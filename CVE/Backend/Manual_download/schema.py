from pydantic import BaseModel, HttpUrl

rep = { "filename_cve": "CVE_start.zip",
        "filename_bdu": "bdu_test_12.xml",
        "update_url_cve": "https://gitea.com/HADUKEN/TEST_CVE/raw/branch/main/CVE_main1.zip",
        "update_url_bdu": "https://github.com/HADUKEN467/TEST_CVE_BDU/raw/master/bdu_test_500.xml",
        "name_base": "bd"
      }

class Repo_Schema(BaseModel):
    filename_cve: str
    filename_bdu: str
    update_url_cve: HttpUrl
    update_url_bdu: HttpUrl
    name_base: str  # без валидации названия бд
