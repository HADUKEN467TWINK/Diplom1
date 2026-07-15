import redis.asyncio as redis
import asyncio


async def setup_redis_and_mongo():
    r = redis.Redis(
        host='my-redis',
        port=6379,
        decode_responses=True
    )

    data = {
        "update_url_cve": "",
        "update_url_bdu": "",
        "name_base": "data_base"
    }

    await r.hset("my_config", mapping=data)
    return r


if __name__ == "__main__":
    asyncio.run(setup_redis_and_mongo())