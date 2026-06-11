"""
MODELO 3 - CRIPTOGRAFIA QUANTICA EM HARDWARE REAL IBM
======================================================
TCC: Protecao de Dados com Criptografia Quantica
Autor: Lucas Vieira

Objetivo:
    Executar uma versao didatica do protocolo BB84 em um computador
    quantico real da IBM, usando Qiskit Runtime e SamplerV2.

Observacoes importantes para o TCC:
    - Este arquivo representa apenas o modelo em hardware real.
      O modelo simulado ja deve permanecer separado.
    - O protocolo implementado e BB84 para distribuicao quantica
      de chaves (QKD). A mensagem nao e criptografada diretamente
      pelo circuito quantico; a chave gerada e usada depois em uma
      demonstracao classica de XOR sobre bits de dados.
    - A interceptacao por Eva e modelada de forma classica, simulando
      o efeito esperado de um ataque interceptar-e-reenviar.
    - O uso de varios shots e majority vote e uma adaptacao para lidar
      com ruido de hardware real. No BB84 fisico puro, cada qubit seria
      transmitido e medido uma unica vez.

Requisitos sugeridos:
    pip install "qiskit[all]~=2.3.1" "qiskit-ibm-runtime~=0.45.1" matplotlib

Configuracao recomendada:
    Defina as variaveis de ambiente:

    Windows PowerShell:
        $env:IBM_QUANTUM_TOKEN="SEU_TOKEN"
        $env:IBM_QUANTUM_INSTANCE="SEU_CRN_DA_INSTANCIA"

    Linux/macOS:
        export IBM_QUANTUM_TOKEN="SEU_TOKEN"
        export IBM_QUANTUM_INSTANCE="SEU_CRN_DA_INSTANCIA"

    O CRN da instancia e obtido na pagina Instances da IBM Quantum.
"""

from __future__ import annotations

import csv
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
# CONFIGURACAO DO EXPERIMENTO EM HARDWARE REAL
# ============================================================

IBM_TOKEN = os.getenv("IBM_QUANTUM_TOKEN")
IBM_INSTANCE = os.getenv("IBM_QUANTUM_INSTANCE")

BACKEND = os.getenv("IBM_BACKEND") or None
N_QUBITS = int(os.getenv("N_QUBITS", "8"))
SHOTS = int(os.getenv("SHOTS", "1024"))
LIMIAR_QBER = 0.11

REPETICOES = int(os.getenv("REPETICOES", "3"))
PASTA_SAIDA = "resultados_ibm_real"


@dataclass
class ResultadoBB84:
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
    chave_alice: List[int]
    chave_bob: List[int]
    payload_bits: List[int]
    payload_cifrado: List[int]
    payload_decifrado: List[int]
    payload_integridade_ok: bool
    contagens_brutas: Dict[str, int]


# ============================================================
# FUNCOES BASICAS DO BB84
# ============================================================

def gerar_bits_aleatorios(n: int) -> List[int]:
    """Gera n bits aleatorios classicos."""
    return [random.randint(0, 1) for _ in range(n)]


def gerar_bases(n: int) -> List[str]:
    """Gera n bases aleatorias: Z ou X."""
    return [random.choice(["Z", "X"]) for _ in range(n)]


def codificar_qubits(bits: List[int], bases: List[str]) -> QuantumCircuit:
    """
    Codifica os bits de Alice em qubits.

    Base Z:
        bit 0 -> |0>
        bit 1 -> |1>, aplicando X

    Base X:
        bit 0 -> |+>, aplicando H
        bit 1 -> |->, aplicando X e H
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
    Aplica a base de medicao de Bob e mede os qubits.

    A medicao padrao do Qiskit ocorre na base Z. Para medir na base X,
    aplica-se H antes da medicao.
    """
    for i, base in enumerate(bases_bob):
        if base == "X":
            circuito.h(i)

    circuito.measure(range(len(bases_bob)), range(len(bases_bob)))
    return circuito


def comparar_bases(bases_alice: List[str], bases_bob: List[str]) -> List[int]:
    """Retorna os indices em que Alice e Bob usaram a mesma base."""
    return [i for i, (a, b) in enumerate(zip(bases_alice, bases_bob)) if a == b]


def calcular_qber(chave_alice: List[int], chave_bob: List[int]) -> float:
    """Calcula a taxa de erro de bits quanticos."""
    if not chave_alice:
        return 0.0

    erros = sum(1 for a, b in zip(chave_alice, chave_bob) if a != b)
    return erros / len(chave_alice)


def calcular_taxa(total_qubits: int, bits_validos: int) -> float:
    """Calcula a taxa de aproveitamento da chave apos comparacao de bases."""
    if total_qubits == 0:
        return 0.0
    return bits_validos / total_qubits


# ============================================================
# INTERCEPTACAO DIDATICA POR EVA
# ============================================================

def simular_interceptacao_eva(bits_alice: List[int], bases_alice: List[str]) -> Tuple[List[int], List[str]]:
    """
    Simula classicamente o ataque interceptar-e-reenviar.

    Eva escolhe bases aleatorias. Quando acerta a base de Alice,
    preserva o bit. Quando erra, o bit retransmitido e tratado como
    aleatorio, elevando a QBER esperada.

    Esta funcao nao cria um terceiro agente fisico dentro do circuito.
    Ela apenas representa, de forma didatica, o efeito da interceptacao.
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
# USO DA CHAVE PARA PROTECAO DE DADOS EM REDE
# ============================================================

def xor_bits(dados: List[int], chave: List[int]) -> List[int]:
    """Aplica XOR entre dados e chave do mesmo tamanho."""
    return [d ^ k for d, k in zip(dados, chave)]


def demonstrar_protecao_dados(chave_alice: List[int], chave_bob: List[int]) -> Tuple[List[int], List[int], List[int], bool]:
    """
    Demonstra o uso da chave BB84 para proteger um pequeno payload binario.

    Como o hardware real pode gerar poucas posicoes validas apos o sifting,
    a demonstracao usa um payload binario com o mesmo tamanho da chave obtida.
    Isso evita depender de 8, 16 ou 24 bits para representar texto ASCII.
    """
    tamanho = min(len(chave_alice), len(chave_bob))

    if tamanho == 0:
        return [], [], [], False

    payload = gerar_bits_aleatorios(tamanho)
    cifrado = xor_bits(payload, chave_alice[:tamanho])
    decifrado = xor_bits(cifrado, chave_bob[:tamanho])
    integridade_ok = payload == decifrado

    return payload, cifrado, decifrado, integridade_ok


# ============================================================
# IBM QUANTUM / HARDWARE REAL
# ============================================================

def nome_backend(backend) -> str:
    """Retorna o nome do backend de forma compativel com diferentes versoes."""
    nome = getattr(backend, "name", None)
    return nome() if callable(nome) else str(nome)


def conectar_ibm():
    """
    Conecta ao IBM Quantum usando Qiskit Runtime.

    Se IBM_TOKEN estiver definido, usa token e instancia via variaveis de ambiente.
    Se nao estiver, tenta usar uma conta ja salva localmente com
    QiskitRuntimeService.save_account().
    """
    print("\nConectando ao IBM Quantum...")

    if IBM_TOKEN:
        service = QiskitRuntimeService(
            channel="ibm_quantum_platform",
            token=IBM_TOKEN,
            instance=IBM_INSTANCE,
        )
    else:
        print("IBM_QUANTUM_TOKEN nao definido. Tentando usar conta salva localmente...")
        service = QiskitRuntimeService()

    if BACKEND:
        backend = service.backend(BACKEND)
    else:
        backend = service.least_busy(
            simulator=False,
            operational=True,
            min_num_qubits=N_QUBITS,
        )

    status = backend.status()
    print(f"Backend selecionado : {nome_backend(backend)}")
    print(f"Qubits disponiveis  : {backend.num_qubits}")
    print(f"Jobs na fila        : {status.pending_jobs}")
    print(f"Operacional         : {status.operational}")

    return service, backend


def extrair_contagens(resultado, registrador: str = "c") -> Dict[str, int]:
    """
    Extrai contagens do resultado do SamplerV2.

    O circuito criado por QuantumCircuit(n, n) usa o registrador classico
    padrao chamado 'c'.
    """
    pub_result = resultado[0]
    bitarray = getattr(pub_result.data, registrador)
    return dict(bitarray.get_counts())


def majority_vote(contagens: Dict[str, int], n_qubits: int) -> List[int]:
    """
    Calcula um bit final por qubit usando voto majoritario.

    No Qiskit, a string de medicao costuma vir com o bit do qubit 0
    na extremidade direita. Por isso, a string e invertida antes
    de associar posicoes aos qubits logicos.
    """
    votos = [[0, 0] for _ in range(n_qubits)]

    for bitstring, frequencia in contagens.items():
        bits = [int(b) for b in reversed(bitstring)]

        for i, bit in enumerate(bits[:n_qubits]):
            votos[i][bit] += frequencia

    return [0 if contagem[0] >= contagem[1] else 1 for contagem in votos]


def executar_bb84_hardware(backend, cenario: str, com_eva: bool, shots: int = SHOTS) -> ResultadoBB84:
    """Executa um cenario do BB84 no hardware real IBM."""
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

    print(f"\nCenario: {cenario}")
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
    chave_alice = [bits_alice[i] for i in indices_validos]
    chave_bob = [bits_bob[i] for i in indices_validos]

    qber = calcular_qber(chave_alice, chave_bob)
    taxa = calcular_taxa(N_QUBITS, len(chave_alice))
    chave_segura = qber <= LIMIAR_QBER and len(chave_alice) > 0

    payload, cifrado, decifrado, integridade_ok = demonstrar_protecao_dados(
        chave_alice,
        chave_bob,
    )

    fim = time.perf_counter()

    return ResultadoBB84(
        cenario=cenario,
        backend=nome_backend(backend),
        job_id=job.job_id(),
        qubits_transmitidos=N_QUBITS,
        bits_validos=len(chave_alice),
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
        chave_alice=chave_alice,
        chave_bob=chave_bob,
        payload_bits=payload,
        payload_cifrado=cifrado,
        payload_decifrado=decifrado,
        payload_integridade_ok=integridade_ok,
        contagens_brutas=contagens,
    )


# ============================================================
# EXIBICAO, SALVAMENTO E GRAFICOS
# ============================================================

def bits_para_string(bits: List[int]) -> str:
    return "".join(str(b) for b in bits)


def exibir_resultado(r: ResultadoBB84) -> None:
    print("\nResultado")
    print("-" * 50)
    print(f"Cenario              : {r.cenario}")
    print(f"Backend              : {r.backend}")
    print(f"Qubits transmitidos  : {r.qubits_transmitidos}")
    print(f"Shots                : {r.shots}")
    print(f"Bits validos         : {r.bits_validos}")
    print(f"Taxa de geracao      : {r.taxa_geracao * 100:.2f}%")
    print(f"QBER                 : {r.qber * 100:.2f}%")
    print(f"Chave segura         : {'Sim' if r.chave_segura else 'Nao'}")
    print(f"Tempo de execucao    : {r.tempo_execucao:.2f}s")
    print(f"Profundidade circuito: {r.profundidade_circuito}")
    print(f"Integridade XOR      : {'OK' if r.payload_integridade_ok else 'Falhou/sem chave'}")

    if r.bits_validos > 0:
        print(f"Chave Alice          : {bits_para_string(r.chave_alice)}")
        print(f"Chave Bob            : {bits_para_string(r.chave_bob)}")
        print(f"Payload              : {bits_para_string(r.payload_bits)}")
        print(f"Payload cifrado      : {bits_para_string(r.payload_cifrado)}")
        print(f"Payload decifrado    : {bits_para_string(r.payload_decifrado)}")


def salvar_resultados(resultados: List[ResultadoBB84], pasta: str = PASTA_SAIDA) -> None:
    os.makedirs(pasta, exist_ok=True)

    dados = [asdict(r) for r in resultados]

    with open(os.path.join(pasta, "resultados_ibm_real.json"), "w", encoding="utf-8") as f:
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
        "payload_integridade_ok",
    ]

    with open(os.path.join(pasta, "resultados_ibm_real.csv"), "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=campos_csv)
        writer.writeheader()
        for r in dados:
            writer.writerow({campo: r[campo] for campo in campos_csv})

    print(f"\nArquivos salvos em: {pasta}/")
    print("- resultados_ibm_real.json")
    print("- resultados_ibm_real.csv")


def calcular_medias_por_cenario(resultados: List[ResultadoBB84]) -> Dict[str, Dict[str, float]]:
    agrupado: Dict[str, List[ResultadoBB84]] = {}

    for r in resultados:
        agrupado.setdefault(r.cenario, []).append(r)

    medias = {}
    for cenario, itens in agrupado.items():
        medias[cenario] = {
            "qber_media": sum(r.qber for r in itens) / len(itens),
            "taxa_media": sum(r.taxa_geracao for r in itens) / len(itens),
            "tempo_medio": sum(r.tempo_execucao for r in itens) / len(itens),
            "bits_validos_media": sum(r.bits_validos for r in itens) / len(itens),
        }

    return medias


def gerar_graficos(resultados: List[ResultadoBB84], pasta: str = PASTA_SAIDA) -> None:
    os.makedirs(pasta, exist_ok=True)
    medias = calcular_medias_por_cenario(resultados)
    cenarios = list(medias.keys())

    # Nomes curtos para evitar poluição visual nos gráficos
    nomes_curtos = {
        "Hardware IBM - sem Eva": "Sem Eva",
        "Hardware IBM - com Eva simulada": "Com Eva",
    }

    # Grafico 1: QBER medio por cenario
    fig, ax = plt.subplots(figsize=(8, 5))
    rotulos_cenarios = [nomes_curtos.get(c, c) for c in cenarios]
    qbers = [medias[c]["qber_media"] * 100 for c in cenarios]

    barras = ax.bar(rotulos_cenarios, qbers, width=0.45)
    ax.axhline(y=LIMIAR_QBER * 100, linestyle="--", label="Limiar QBER 11%")
    ax.set_title("QBER médio no hardware real IBM")
    ax.set_ylabel("QBER (%)")
    ax.set_ylim(0, max(40, max(qbers, default=0) + 5))
    ax.grid(True, axis="y", alpha=0.3)
    ax.legend()

    for barra, valor in zip(barras, qbers):
        ax.text(
            barra.get_x() + barra.get_width() / 2,
            barra.get_height() + 1,
            f"{valor:.1f}%",
            ha="center",
            va="bottom",
            fontsize=9,
        )

    plt.tight_layout()
    plt.savefig(os.path.join(pasta, "ibm_real_qber.png"), dpi=150)
    plt.close()

    # Grafico 2: taxa media de geracao
    fig, ax = plt.subplots(figsize=(8, 5))
    taxas = [medias[c]["taxa_media"] * 100 for c in cenarios]

    barras = ax.bar(rotulos_cenarios, taxas, width=0.45)
    ax.set_title("Taxa média de geração da chave no hardware real IBM")
    ax.set_ylabel("Taxa de geração (%)")
    ax.set_ylim(0, 100)
    ax.grid(True, axis="y", alpha=0.3)

    for barra, valor in zip(barras, taxas):
        ax.text(
            barra.get_x() + barra.get_width() / 2,
            barra.get_height() + 1,
            f"{valor:.1f}%",
            ha="center",
            va="bottom",
            fontsize=9,
        )

    plt.tight_layout()
    plt.savefig(os.path.join(pasta, "ibm_real_taxa_geracao.png"), dpi=150)
    plt.close()

    # Grafico 3: QBER por execucao, com rotulos curtos e numeracao por cenario
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
    ax.set_title("QBER por execução no hardware real IBM")
    ax.set_ylabel("QBER (%)")
    ax.set_ylim(0, max(40, max(valores, default=0) + 5))
    ax.grid(True, axis="y", alpha=0.3)
    ax.legend()

    for barra, valor in zip(barras, valores):
        ax.text(
            barra.get_x() + barra.get_width() / 2,
            barra.get_height() + 1,
            f"{valor:.1f}%",
            ha="center",
            va="bottom",
            fontsize=8,
        )

    plt.tight_layout()
    plt.savefig(os.path.join(pasta, "ibm_real_qber_por_execucao.png"), dpi=150)
    plt.close()

    print("Graficos gerados:")
    print("- ibm_real_qber.png")
    print("- ibm_real_taxa_geracao.png")
    print("- ibm_real_qber_por_execucao.png")


def imprimir_resumo_final(resultados: List[ResultadoBB84]) -> None:
    medias = calcular_medias_por_cenario(resultados)

    print("\nResumo final por cenario")
    print("-" * 70)
    for cenario, m in medias.items():
        print(
            f"{cenario}: "
            f"QBER medio={m['qber_media'] * 100:.2f}% | "
            f"Taxa media={m['taxa_media'] * 100:.2f}% | "
            f"Bits validos medio={m['bits_validos_media']:.2f} | "
            f"Tempo medio={m['tempo_medio']:.2f}s"
        )


# ============================================================
# EXECUCAO PRINCIPAL
# ============================================================

if __name__ == "__main__":
    print("\nTCC - Protecao de Dados com Criptografia Quantica")
    print("Modelo 3 - BB84 em hardware real IBM")
    print("=" * 60)

    print(f"N_QUBITS   : {N_QUBITS}")
    print(f"SHOTS      : {SHOTS}")
    print(f"REPETICOES : {REPETICOES}")

    _service, backend = conectar_ibm()

    resultados: List[ResultadoBB84] = []

    cenarios = [
        ("Hardware IBM - sem Eva", False),
        ("Hardware IBM - com Eva simulada", True),
    ]

    for nome_cenario, com_eva in cenarios:
        for i in range(REPETICOES):
            print(f"\nExecucao {i + 1}/{REPETICOES} - {nome_cenario}")
            resultado = executar_bb84_hardware(
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

    print("\nExecucao concluida.")
