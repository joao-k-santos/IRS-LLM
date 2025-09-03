import asyncio
import contextualizer
import rule_generator
import server
import utils
import llm_client
import aiohttp

async def esperar_servidor(url, timeout=60):
    print(f"[Watcher] Aguardando o servidor estar online em {url}...")
    async with aiohttp.ClientSession() as session:
        for i in range(timeout):
            try:
                async with session.get(url) as resp:
                    if resp.status == 200:
                        print(f"[Watcher] Servidor online! ({url})")
                        return
            except Exception:
                pass
            await asyncio.sleep(1)
        raise TimeoutError(f"Servidor {url} não respondeu em {timeout} segundos.")

async def verificar_novos_ataques():
    await esperar_servidor(f"{llm_client.SERVER_URL}/healthcheck")

    watcher_llm_token = contextualizer.obter_token("api_llm", contextualizer.LLM_URL)
    watcher_nids_token = contextualizer.obter_token("api_nids", contextualizer.NIDS_URL)

    while True:
        print("[Watcher] Verificando novos ataques...")
        novos_ataques = contextualizer.buscar_classificados(token=watcher_nids_token)

        if novos_ataques:
            print(f"[Watcher] {len(novos_ataques)} novos ataques detectados!")
            print("[Watcher] Detalhes dos ataques:", novos_ataques)

            lotes = utils.dividir_em_lotes(novos_ataques, tamanho_lote=3)
            print(f"[Watcher] Fragmentando ataques em {len(lotes)} lotes.")

            for i, lote in enumerate(lotes):
                print(f"[Watcher] Processando lote {i+1}/{len(lotes)} com {len(lote)} ataques...")

                try:
                    print("[Watcher] Gerando contexto...")
                    contexto = await contextualizer.gerar_contexto_para_lote(
                        lote,
                        model=llm_client.MODEL,
                        token=watcher_llm_token
                    )
                    print("[Watcher] Contexto gerado:", contexto)

                    contexto_tratado = utils.extrair_json_de_resposta(contexto)
                    print("[Watcher] Contexto tratado:", contexto_tratado)
                    if not contexto_tratado:
                        print("[Watcher] Contexto vazio ou inválido, pulando lote.")
                        continue
                    await contextualizer.registrar_ataque(contexto_tratado, token=watcher_llm_token)

                    print("[Watcher] Gerando regras para o lote...")
                    regras = await rule_generator.gerar_regras(
                        model=llm_client.MODEL,
                        token=watcher_llm_token
                    )
                    regras_tratadas = utils.extrair_json_de_resposta(regras)
                    print("[Watcher] Regras geradas:", regras_tratadas)

                    flow_ids = [ataque["flow_id"] for ataque in contexto_tratado] if isinstance(contexto_tratado, list) else [contexto_tratado["flow_id"]]

                    for regra in regras_tratadas:
                        rule_generator.registrar_regra(
                            tipo=regra["tipo"],
                            descricao=regra["descricao"],
                            comando=regra["comando"],
                            ataques=flow_ids,
                            token=watcher_llm_token
                        )

                    for flow_id in flow_ids:
                        print(f"[Watcher] Atualizando ataque {flow_id} como processado...")
                        contextualizer.atualizar_classificado(flow_id, token=watcher_nids_token)

                except Exception as e:
                    print(f"[Watcher] Erro ao processar lote {i+1}: {e}")

        await asyncio.sleep(5)

def iniciar_watcher():
    print("[Watcher] Iniciando monitoramento assíncrono...")
    asyncio.run(verificar_novos_ataques())

if __name__ == "__main__":
    iniciar_watcher()
