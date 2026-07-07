import redis.asyncio as redis
import asyncio


async def setup_redis_and_mongo():
    # Подключаемся к Redis
    r = redis.Redis(
        host='my-redis',
        port=6379,
        decode_responses=True
    )

    data = {
        "mongodb_url": "mongodb://host.docker.internal:27017/",
        "filename_cve": "CVE_start.zip",
        "filename_bdu": "bdu_test_12.xml",
        "update_url_cve": "https://gitea.com/HADUKEN/TEST_CVE/raw/branch/main/CVE_main1.zip",
        "update_url_bdu": "https://github.com/HADUKEN467/TEST_CVE_BDU/raw/master/bdu_test_500.xml",
        "name_base": "bd"
    }

    await r.hset("my_config", mapping=data)
    return r


if __name__ == "__main__":
    asyncio.run(setup_redis_and_mongo())

# HSET my_config mongodb_url "mongodb://host.docker.internal:27017/"
# HSET my_config filename_cve "CVE_start.zip"
# HSET my_config filename_bdu "bdu_test_12.xml"
# HSET my_config update_url_cve "https://gitea.com/HADUKEN/TEST_CVE/raw/branch/main/CVE_main1.zip"
# HSET my_config update_url_bdu "https://github.com/HADUKEN467/TEST_CVE_BDU/raw/master/bdu_test_500.xml"
# HSET my_config name_base "bd"