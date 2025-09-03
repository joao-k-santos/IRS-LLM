import aiohttp

SERVER_URL = "http://localhost:8000"
MODEL = "meu-modelo"

async def gerar_contexto(token, model=MODEL):
    async with aiohttp.ClientSession() as session:
        async with session.post(
            f"{SERVER_URL}/gerar_contexto",
            headers={"Authorization": f"Bearer {token}"},
            json={"model": model},
            timeout=120
        ) as resp:
            if resp.status != 200:
                raise Exception(f"Erro ao gerar contexto: {resp.status} - {await resp.text()}")
            return await resp.json()

async def gerar_regras(token, model=MODEL):
    async with aiohttp.ClientSession() as session:
        async with session.post(
            f"{SERVER_URL}/gerar_regras",
            headers={"Authorization": f"Bearer {token}"},
            json={"model": model},
            timeout=120
        ) as resp:
            if resp.status != 200:
                raise Exception(f"Erro ao gerar regras: {resp.status} - {await resp.text()}")
            return await resp.json()
