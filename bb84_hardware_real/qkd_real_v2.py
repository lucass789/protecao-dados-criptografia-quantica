"""
MODELO 3 - BB84 APRIMORADO EM HARDWARE REAL IBM
================================================
TCC: Proteção de Dados com Criptografia Quântica
Autor: Lucas Vieira

Objetivo:
    Executar uma versão aprimorada e didática do protocolo BB84 em
    hardware quântico real da IBM, mantendo alinhamento com o modelo
    simulado já documentado no TCC.

Importante:
    - Este modelo continua baseado no BB84.
    - Não utiliza E91 nem protocolos baseados em entrelaçamento.
    - A melhoria está no tratamento experimental:
        * mais qubits por padrão;
        * coleta de métricas mais estável;
        * pós-processamento clássico didático;
        * geração de gráficos mais limpos;
        * salvamento de JSON/CSV;
        * registro de backend, job_id, profundidade e portas.
    - A reconciliação e a amplificação de privacidade são representações
      didáticas de pós-processamento clássico. Elas não substituem uma
      implementação completa de QKD comercial.

Requisitos:
    pip install qiskit qiskit-ibm-runtime matplotlib

Variáveis de ambiente:
    PowerShell:
        $env:IBM_QUANTUM_TOKEN='SEU_TOKEN'
        $env:IBM_QUANTUM_INSTANCE='SEU_CRN_DA_INSTANCIA'

    Linux/macOS:
        export IBM_QUANTUM_TOKEN='SEU_TOKEN'
        export IBM_QUANTUM_INSTANCE='SEU_CRN_DA_INSTANCIA'

Parâmetros opcionais:
    $env:N_QUBITS='16'
    $env:SHOTS='1024'
    $env:REPETICOES='3'
    $env:IBM_BACKEND_PREFERIDO='nome_do_backend'
"""

from __future__ import annotations

import csv
import hashlib
import json
import os
import random
import time
from dataclasses import dataclass, asdict
from typing import Dict, List, Tuple

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from qiskit import QuantumCircuit
from qiskit.transpiler import generate_preset_pass_manager
from qiskit_ibm_runtime import QiskitRuntimeService, SamplerV2


# ============================================================
# CONFIGURAÇÃO
# ============================================================

IBM_TOKEN = os.getenv("IBM_QUANTUM_TOKEN")
IBM_INSTANCE = os.getenv("IBM_QUANTUM_INSTANCE")
BACKEND_PREFERIDO = os.getenv("IBM_BACKEND_PREFERIDO") or None

# Mantém o experimento viável, mas melhora a estabilidade em relação a 8 qubits.
N_QUBITS = int(os.getenv("N_QUBITS", "16"))

# Vários shots são usados para reduzir instabilidade de leitura em hardware real.
# Para uma demonstração mais próxima do BB84 puro, pode-se usar SHOTS=1.
SHOTS = int(os.getenv("SHOTS", "1024"))

# Repetições do experimento por cenário.
REPETICOES = int(os.getenv("REPETICOES", "3"))

# Limiar didático usado no TCC.
LIMIAR_QBER = 0.11

PASTA_SAIDA = "resultados_ibm_bb84_aprimorado"


@dataclass
class ResultadoBB84Aprimorado:
    cenario: str
    backend: str
    job_id: str
    qubits_transmitidos: int
    bits_validos: int
    taxa_geracao: float
    qber: float
    chave_segura: bool
    shots: int
    tempo_execucao: float
    profundidade_circuito: int
    portas_circuito: Dict[str, int]
    bits_alice: List[int]
    bases_alice: List[str]
    bases_bob: List[str]
    chave_bruta_alice: List[int]
    chave_bruta_bob: List[int]
    erros_detectados: int
    bits_corrigidos_reconciliacao: int
    chave_reconciliada_alice: List[int]
    chave_reconciliada_bob: List[int]
    chave_final_alice_hash: str
    chave_final_bob_hash: str
    chave_final_integridade_ok: bool
    tamanho_chave_final_bits: int
    payload_bits: List[int]
    payload_cifrado: List[int]
    payload_decifrado: List[int]
    payload_integridade_ok: bool
    contagens_brutas: Dict[str, int]


# ============================================================
# FUNÇÕES BÁSICAS DO BB84
# ============================================================

def gerar_bits_aleatorios(n: int) -> List[int]:
    return [random.randint(0, 1) for _ in range(n)]


def gerar_bases(n: int) -> List[str]:
    return [random.choice(["Z", "X"]) for _ in range(n)]


def codificar_qubits(bits: List[int], bases: List[str]) -> QuantumCircuit:
    """
    Codifica bits em qubits seguindo o BB84:
    - Base Z: |0> ou |1>
    - Base X: |+> ou |->
    """
    n = len(bits)
    circuito = QuantumCircuit(n, n)

    for i in range(n):
        if bits[i] == 1:
            circuito.x(i)
        if bases[i] == "X":
            circuito.h(i)

    circuito.barrier()
    return circuito


def medir_qubits(circuito: QuantumCircuit, bases_bob: List[str]) -> QuantumCircuit:
    """
    Mede qubits nas bases escolhidas por Bob.
    A medição padrão do Qiskit é na base Z.
    Para medir em X, aplica-se H antes da medição.
    """
    for i, base in enumerate(bases_bob):
        if base == "X":
            circuito.h(i)

    circuito.measure(range(len(bases_bob)), range(len(bases_bob)))
    return circuito


def comparar_bases(bases_alice: List[str], bases_bob: List[str]) -> List[int]:
    return [i for i, (a, b) in enumerate(zip(bases_alice, bases_bob)) if a == b]


def calcular_qber(chave_alice: List[int], chave_bob: List[int]) -> Tuple[float, int]:
    if not chave_alice:
        return 0.0, 0

    erros = sum(1 for a, b in zip(chave_alice, chave_bob) if a != b)
    return erros / len(chave_alice), erros


def calcular_taxa(total_qubits: int, bits_validos: int) -> float:
    if total_qubits == 0:
        return 0.0
    return bits_validos / total_qubits


# ============================================================
# INTERCEPTAÇÃO DIDÁTICA POR EVA
# ============================================================

def simular_interceptacao_eva(bits_alice: List[int], bases_alice: List[str]) -> Tuple[List[int], List[str]]:
    """
    Simula o efeito clássico do ataque interceptar-e-reenviar.

    Eva escolhe bases aleatórias. Quando acerta a base de Alice,
    preserva o bit. Quando erra, retransmite um bit aleatório.
    """
    bases_eva = gerar_bases(len(bits_alice))
    bits_reenviados = []

    for bit, base_alice, base_eva in zip(bits_alice, bases_alice, bases_eva):
        if base_alice == base_eva:
            bits_reenviados.append(bit)
        else:
            bits_reenviados.append(random.randint(0, 1))

    return bits_reenviados, bases_eva


# ============================================================
# PÓS-PROCESSAMENTO CLÁSSICO
# ============================================================

def reconciliacao_didatica(chave_alice: List[int], chave_bob: List[int]) -> Tuple[List[int], List[int], int]:
    """
    Representação didática da reconciliação de informação.

    Bob é ajustado para a chave de Alice apenas quando a QBER está dentro do limiar aceito.
    """
    chave_corrigida_bob = chave_bob.copy()
    corrigidos = 0

    for i in range(len(chave_alice)):
        if chave_corrigida_bob[i] != chave_alice[i]:
            chave_corrigida_bob[i] = chave_alice[i]
            corrigidos += 1

    return chave_alice.copy(), chave_corrigida_bob, corrigidos


def bits_para_string(bits: List[int]) -> str:
    return "".join(str(b) for b in bits)


def amplificacao_privacidade_didatica(bits: List[int], tamanho_saida_bits: int = 128) -> str:
    """
    Representação didática de amplificação de privacidade usando SHA-256.
    """
    if not bits:
        return ""

    texto_bits = bits_para_string(bits).encode("utf-8")
    digest = hashlib.sha256(texto_bits).hexdigest()

    # Cada caractere hexadecimal representa 4 bits.
    caracteres = max(1, tamanho_saida_bits // 4)
    return digest[:caracteres]


def xor_bits(dados: List[int], chave: List[int]) -> List[int]:
    return [d ^ k for d, k in zip(dados, chave)]


def demonstrar_protecao_dados(chave_alice: List[int], chave_bob: List[int]) -> Tuple[List[int], List[int], List[int], bool]:
    tamanho = min(len(chave_alice), len(chave_bob))

    if tamanho == 0:
        return [], [], [], False

    payload = gerar_bits_aleatorios(tamanho)
    cifrado = xor_bits(payload, chave_alice[:tamanho])
    decifrado = xor_bits(cifrado, chave_bob[:tamanho])
    return payload, cifrado, decifrado, payload == decifrado


# ============================================================
# IBM QUANTUM / HARDWARE REAL
# ============================================================

def nome_backend(backend) -> str:
    nome = getattr(backend, "name", None)
    return nome() if callable(nome) else str(nome)


def conectar_ibm():
    print("\nConectando ao IBM Quantum...")

    if IBM_TOKEN:
        service = QiskitRuntimeService(
            channel="ibm_quantum_platform",
            token=IBM_TOKEN,
            instance=IBM_INSTANCE,
        )
    else:
        print("IBM_QUANTUM_TOKEN não definido. Tentando usar conta salva localmente...")
        service = QiskitRuntimeService()

    if BACKEND_PREFERIDO:
        backend = service.backend(BACKEND_PREFERIDO)
    else:
        backend = service.least_busy(
            simulator=False,
            operational=True,
            min_num_qubits=N_QUBITS,
        )

    status = backend.status()
    print(f"Backend selecionado : {nome_backend(backend)}")
    print(f"Qubits disponíveis  : {backend.num_qubits}")
    print(f"Jobs na fila        : {status.pending_jobs}")
    print(f"Operacional         : {status.operational}")

    return service, backend


def extrair_contagens(resultado, registrador: str = "c") -> Dict[str, int]:
    pub_result = resultado[0]
    bitarray = getattr(pub_result.data, registrador)
    return dict(bitarray.get_counts())


def majority_vote(contagens: Dict[str, int], n_qubits: int) -> List[int]:
    """
    Estima um bit final por qubit usando voto majoritário.

    No Qiskit, o bit do qubit 0 geralmente aparece na extremidade direita
    da string de medição, por isso a string é invertida.
    """
    votos = [[0, 0] for _ in range(n_qubits)]

    for bitstring, frequencia in contagens.items():
        bits = [int(b) for b in reversed(bitstring)]

        for i, bit in enumerate(bits[:n_qubits]):
            votos[i][bit] += frequencia

    return [0 if contagem[0] >= contagem[1] else 1 for contagem in votos]


def executar_bb84_hardware_aprimorado(
    backend,
    cenario: str,
    com_eva: bool,
    shots: int = SHOTS,
) -> ResultadoBB84Aprimorado:
    inicio = time.perf_counter()

    bits_alice = gerar_bits_aleatorios(N_QUBITS)
    bases_alice = gerar_bases(N_QUBITS)
    bases_bob = gerar_bases(N_QUBITS)

    if com_eva:
        bits_envio, _bases_eva = simular_interceptacao_eva(bits_alice, bases_alice)
        bases_envio = bases_alice
    else:
        bits_envio = bits_alice
        bases_envio = bases_alice

    circuito = codificar_qubits(bits_envio, bases_envio)
    circuito = medir_qubits(circuito, bases_bob)

    print(f"\nCenário: {cenario}")
    print("Transpilando circuito para o hardware real...")

    pass_manager = generate_preset_pass_manager(
        backend=backend,
        optimization_level=1,
    )
    circuito_isa = pass_manager.run(circuito)

    profundidade = circuito_isa.depth()
    portas = dict(circuito_isa.count_ops())

    print(f"Profundidade do circuito : {profundidade}")
    print(f"Portas do circuito       : {portas}")
    print(f"Enviando job com {shots} shots...")

    sampler = SamplerV2(mode=backend)
    job = sampler.run([circuito_isa], shots=shots)
    print(f"Job ID: {job.job_id()}")

    resultado = job.result()
    contagens = extrair_contagens(resultado)
    bits_bob = majority_vote(contagens, N_QUBITS)

    indices_validos = comparar_bases(bases_alice, bases_bob)
    chave_bruta_alice = [bits_alice[i] for i in indices_validos]
    chave_bruta_bob = [bits_bob[i] for i in indices_validos]

    qber, erros_detectados = calcular_qber(chave_bruta_alice, chave_bruta_bob)
    taxa = calcular_taxa(N_QUBITS, len(chave_bruta_alice))
    chave_segura = qber <= LIMIAR_QBER and len(chave_bruta_alice) > 0

    if chave_segura:
        chave_rec_alice, chave_rec_bob, bits_corrigidos = reconciliacao_didatica(
            chave_bruta_alice,
            chave_bruta_bob,
        )

        # A chave final é menor que a bruta, representando compressão pós-processamento.
        tamanho_final_bits = min(128, max(8, len(chave_rec_alice) * 4))
        chave_hash_alice = amplificacao_privacidade_didatica(
            chave_rec_alice,
            tamanho_saida_bits=tamanho_final_bits,
        )
        chave_hash_bob = amplificacao_privacidade_didatica(
            chave_rec_bob,
            tamanho_saida_bits=tamanho_final_bits,
        )
    else:
        chave_rec_alice = []
        chave_rec_bob = []
        bits_corrigidos = 0
        chave_hash_alice = ""
        chave_hash_bob = ""
        tamanho_final_bits = 0

    chave_final_integridade_ok = chave_hash_alice == chave_hash_bob and chave_hash_alice != ""

    payload, cifrado, decifrado, integridade_ok = demonstrar_protecao_dados(
        chave_rec_alice,
        chave_rec_bob,
    )

    fim = time.perf_counter()

    return ResultadoBB84Aprimorado(
        cenario=cenario,
        backend=nome_backend(backend),
        job_id=job.job_id(),
        qubits_transmitidos=N_QUBITS,
        bits_validos=len(chave_bruta_alice),
        taxa_geracao=taxa,
        qber=qber,
        chave_segura=chave_segura,
        shots=shots,
        tempo_execucao=fim - inicio,
        profundidade_circuito=profundidade,
        portas_circuito=portas,
        bits_alice=bits_alice,
        bases_alice=bases_alice,
        bases_bob=bases_bob,
        chave_bruta_alice=chave_bruta_alice,
        chave_bruta_bob=chave_bruta_bob,
        erros_detectados=erros_detectados,
        bits_corrigidos_reconciliacao=bits_corrigidos,
        chave_reconciliada_alice=chave_rec_alice,
        chave_reconciliada_bob=chave_rec_bob,
        chave_final_alice_hash=chave_hash_alice,
        chave_final_bob_hash=chave_hash_bob,
        chave_final_integridade_ok=chave_final_integridade_ok,
        tamanho_chave_final_bits=tamanho_final_bits,
        payload_bits=payload,
        payload_cifrado=cifrado,
        payload_decifrado=decifrado,
        payload_integridade_ok=integridade_ok,
        contagens_brutas=contagens,
    )


# ============================================================
# EXIBIÇÃO, SALVAMENTO E GRÁFICOS
# ============================================================

def exibir_resultado(r: ResultadoBB84Aprimorado) -> None:
    print("\nResultado")
    print("-" * 60)
    print(f"Cenário                    : {r.cenario}")
    print(f"Backend                    : {r.backend}")
    print(f"Job ID                     : {r.job_id}")
    print(f"Qubits transmitidos        : {r.qubits_transmitidos}")
    print(f"Shots                      : {r.shots}")
    print(f"Bits válidos               : {r.bits_validos}")
    print(f"Taxa de geração            : {r.taxa_geracao * 100:.2f}%")
    print(f"QBER                       : {r.qber * 100:.2f}%")
    print(f"Erros detectados           : {r.erros_detectados}")
    print(f"Chave segura               : {'Sim' if r.chave_segura else 'Não'}")
    print(f"Bits corrigidos            : {r.bits_corrigidos_reconciliacao}")
    print(f"Chave final íntegra        : {'Sim' if r.chave_final_integridade_ok else 'Não'}")
    print(f"Payload XOR íntegro        : {'Sim' if r.payload_integridade_ok else 'Não/Falhou'}")
    print(f"Tempo de execução          : {r.tempo_execucao:.2f}s")
    print(f"Profundidade do circuito   : {r.profundidade_circuito}")

    if r.bits_validos > 0:
        print(f"Chave bruta Alice          : {bits_para_string(r.chave_bruta_alice)}")
        print(f"Chave bruta Bob            : {bits_para_string(r.chave_bruta_bob)}")

    if r.chave_final_alice_hash:
        print(f"Hash chave final Alice     : {r.chave_final_alice_hash}")
        print(f"Hash chave final Bob       : {r.chave_final_bob_hash}")


def salvar_resultados(resultados: List[ResultadoBB84Aprimorado], pasta: str = PASTA_SAIDA) -> None:
    os.makedirs(pasta, exist_ok=True)

    dados = [asdict(r) for r in resultados]

    with open(os.path.join(pasta, "resultados_ibm_bb84_aprimorado.json"), "w", encoding="utf-8") as f:
        json.dump(dados, f, indent=4, ensure_ascii=False)

    campos_csv = [
        "cenario",
        "backend",
        "job_id",
        "qubits_transmitidos",
        "bits_validos",
        "taxa_geracao",
        "qber",
        "chave_segura",
        "shots",
        "tempo_execucao",
        "profundidade_circuito",
        "erros_detectados",
        "bits_corrigidos_reconciliacao",
        "chave_final_integridade_ok",
        "payload_integridade_ok",
    ]

    with open(os.path.join(pasta, "resultados_ibm_bb84_aprimorado.csv"), "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=campos_csv)
        writer.writeheader()
        for r in dados:
            writer.writerow({campo: r[campo] for campo in campos_csv})

    print(f"\nArquivos salvos em: {pasta}/")
    print("- resultados_ibm_bb84_aprimorado.json")
    print("- resultados_ibm_bb84_aprimorado.csv")


def calcular_medias_por_cenario(resultados: List[ResultadoBB84Aprimorado]) -> Dict[str, Dict[str, float]]:
    agrupado: Dict[str, List[ResultadoBB84Aprimorado]] = {}

    for r in resultados:
        agrupado.setdefault(r.cenario, []).append(r)

    medias = {}
    for cenario, itens in agrupado.items():
        medias[cenario] = {
            "qber_media": sum(r.qber for r in itens) / len(itens),
            "taxa_media": sum(r.taxa_geracao for r in itens) / len(itens),
            "tempo_medio": sum(r.tempo_execucao for r in itens) / len(itens),
            "bits_validos_media": sum(r.bits_validos for r in itens) / len(itens),
            "erros_media": sum(r.erros_detectados for r in itens) / len(itens),
        }

    return medias


def gerar_graficos(resultados: List[ResultadoBB84Aprimorado], pasta: str = PASTA_SAIDA) -> None:
    os.makedirs(pasta, exist_ok=True)
    medias = calcular_medias_por_cenario(resultados)
    cenarios = list(medias.keys())

    nomes_curtos = {
        "BB84 IBM - sem Eva": "Sem Eva",
        "BB84 IBM - com Eva simulada": "Com Eva",
    }

    rotulos_cenarios = [nomes_curtos.get(c, c) for c in cenarios]

    # Gráfico 1: QBER médio
    fig, ax = plt.subplots(figsize=(8, 5))
    qbers = [medias[c]["qber_media"] * 100 for c in cenarios]
    barras = ax.bar(rotulos_cenarios, qbers, width=0.45)
    ax.axhline(y=LIMIAR_QBER * 100, linestyle="--", label="Limiar QBER 11%")
    ax.set_title("QBER médio — BB84 aprimorado em hardware IBM")
    ax.set_ylabel("QBER (%)")
    ax.set_ylim(0, max(40, max(qbers, default=0) + 5))
    ax.grid(True, axis="y", alpha=0.3)
    ax.legend()

    for barra, valor in zip(barras, qbers):
        ax.text(barra.get_x() + barra.get_width() / 2, barra.get_height() + 1,
                f"{valor:.1f}%", ha="center", va="bottom", fontsize=9)

    plt.tight_layout()
    plt.savefig(os.path.join(pasta, "bb84_aprimorado_qber_medio.png"), dpi=150)
    plt.close()

    # Gráfico 2: taxa média de geração
    fig, ax = plt.subplots(figsize=(8, 5))
    taxas = [medias[c]["taxa_media"] * 100 for c in cenarios]
    barras = ax.bar(rotulos_cenarios, taxas, width=0.45)
    ax.set_title("Taxa média de geração da chave — BB84 aprimorado")
    ax.set_ylabel("Taxa de geração (%)")
    ax.set_ylim(0, 100)
    ax.grid(True, axis="y", alpha=0.3)

    for barra, valor in zip(barras, taxas):
        ax.text(barra.get_x() + barra.get_width() / 2, barra.get_height() + 1,
                f"{valor:.1f}%", ha="center", va="bottom", fontsize=9)

    plt.tight_layout()
    plt.savefig(os.path.join(pasta, "bb84_aprimorado_taxa_geracao.png"), dpi=150)
    plt.close()

    # Gráfico 3: QBER por execução
    fig, ax = plt.subplots(figsize=(10, 5))
    rotulos = []
    valores = []
    contador_por_cenario: Dict[str, int] = {}

    for r in resultados:
        nome_curto = nomes_curtos.get(r.cenario, r.cenario)
        contador_por_cenario[nome_curto] = contador_por_cenario.get(nome_curto, 0) + 1
        rotulos.append(f"{nome_curto}\nExec. {contador_por_cenario[nome_curto]}")
        valores.append(r.qber * 100)

    barras = ax.bar(rotulos, valores, width=0.45)
    ax.axhline(y=LIMIAR_QBER * 100, linestyle="--", label="Limiar QBER 11%")
    ax.set_title("QBER por execução — BB84 aprimorado em hardware IBM")
    ax.set_ylabel("QBER (%)")
    ax.set_ylim(0, max(40, max(valores, default=0) + 5))
    ax.grid(True, axis="y", alpha=0.3)
    ax.legend()

    for barra, valor in zip(barras, valores):
        ax.text(barra.get_x() + barra.get_width() / 2, barra.get_height() + 1,
                f"{valor:.1f}%", ha="center", va="bottom", fontsize=8)

    plt.tight_layout()
    plt.savefig(os.path.join(pasta, "bb84_aprimorado_qber_por_execucao.png"), dpi=150)
    plt.close()

    print("Gráficos gerados:")
    print("- bb84_aprimorado_qber_medio.png")
    print("- bb84_aprimorado_taxa_geracao.png")
    print("- bb84_aprimorado_qber_por_execucao.png")


def imprimir_resumo_final(resultados: List[ResultadoBB84Aprimorado]) -> None:
    medias = calcular_medias_por_cenario(resultados)

    print("\nResumo final por cenário")
    print("-" * 80)
    for cenario, m in medias.items():
        print(
            f"{cenario}: "
            f"QBER médio={m['qber_media'] * 100:.2f}% | "
            f"Taxa média={m['taxa_media'] * 100:.2f}% | "
            f"Bits válidos médio={m['bits_validos_media']:.2f} | "
            f"Erros médio={m['erros_media']:.2f} | "
            f"Tempo médio={m['tempo_medio']:.2f}s"
        )


# ============================================================
# EXECUÇÃO PRINCIPAL
# ============================================================

if __name__ == "__main__":
    print("\nTCC - Proteção de Dados com Criptografia Quântica")
    print("Modelo 3 - BB84 aprimorado em hardware real IBM")
    print("=" * 70)

    print(f"N_QUBITS   : {N_QUBITS}")
    print(f"SHOTS      : {SHOTS}")
    print(f"REPETIÇÕES : {REPETICOES}")

    _service, backend = conectar_ibm()

    resultados: List[ResultadoBB84Aprimorado] = []

    cenarios = [
        ("BB84 IBM - sem Eva", False),
        ("BB84 IBM - com Eva simulada", True),
    ]

    for nome_cenario, com_eva in cenarios:
        for i in range(REPETICOES):
            print(f"\nExecução {i + 1}/{REPETICOES} - {nome_cenario}")
            resultado = executar_bb84_hardware_aprimorado(
                backend=backend,
                cenario=nome_cenario,
                com_eva=com_eva,
                shots=SHOTS,
            )
            exibir_resultado(resultado)
            resultados.append(resultado)

    salvar_resultados(resultados)
    gerar_graficos(resultados)
    imprimir_resumo_final(resultados)

    print("\nExecução concluída.")
