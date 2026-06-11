"""
MODELO 2 — CRIPTOGRAFIA QUÂNTICA SIMULADA
Protocolo BB84 com Qiskit AerSimulator

Trabalho de Conclusão de Curso:
Proteção de Dados com Criptografia Quântica

Este código implementa uma versão simplificada do protocolo BB84,
com foco acadêmico e experimental. O objetivo é simular a geração
de uma chave quântica entre Alice e Bob, avaliando a QBER, a taxa
de geração da chave e o impacto de ruído e interceptação.
"""

import random
import time
import os
import matplotlib.pyplot as plt

from qiskit import QuantumCircuit
from qiskit_aer import AerSimulator


# ============================================================
# FUNÇÕES BÁSICAS DO PROTOCOLO BB84
# ============================================================

def gerar_bits_aleatorios(n):
    """
    Gera uma lista de bits aleatórios, com valores 0 ou 1.
    Esses bits representam a sequência inicial escolhida por Alice.
    """
    bits = []

    for _ in range(n):
        bits.append(random.randint(0, 1))

    return bits


def gerar_bases(n):
    """
    Gera uma lista de bases aleatórias.
    No protocolo BB84, são utilizadas duas bases:
    Z: base computacional
    X: base diagonal
    """
    bases = []

    for _ in range(n):
        bases.append(random.choice(["Z", "X"]))

    return bases


def codificar_qubits(bits, bases):
    """
    Codifica os bits de Alice em qubits, de acordo com as bases escolhidas.

    Regras utilizadas:
    - Bit 0 na base Z: mantém o estado |0>
    - Bit 1 na base Z: aplica a porta X, gerando |1>
    - Bit 0 na base X: aplica a porta H, gerando |+>
    - Bit 1 na base X: aplica X e depois H, gerando |->
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


def medir_qubits(circuito, bases_bob):
    """
    Realiza a medição dos qubits de acordo com as bases escolhidas por Bob.

    A medição padrão ocorre na base Z. Para medir na base X, aplica-se
    uma porta Hadamard antes da medição.
    """
    n = len(bases_bob)

    for i in range(n):
        if bases_bob[i] == "X":
            circuito.h(i)

    circuito.measure(range(n), range(n))
    return circuito


def comparar_bases(bases_alice, bases_bob):
    """
    Compara as bases escolhidas por Alice e Bob.

    Apenas os índices em que as bases coincidem são utilizados
    para formar a chave bruta compartilhada.
    """
    indices_validos = []

    for i in range(len(bases_alice)):
        if bases_alice[i] == bases_bob[i]:
            indices_validos.append(i)

    return indices_validos


def calcular_qber(chave_alice, chave_bob):
    """
    Calcula a QBER (Quantum Bit Error Rate).

    QBER = número de bits diferentes / número total de bits comparados
    """
    if len(chave_alice) == 0:
        return 0

    erros = 0

    for i in range(len(chave_alice)):
        if chave_alice[i] != chave_bob[i]:
            erros += 1

    return erros / len(chave_alice)


def calcular_taxa(total_qubits, bits_validos):
    """
    Calcula a taxa de geração da chave.

    Essa taxa representa a proporção de bits aproveitados após
    a comparação das bases de Alice e Bob.
    """
    if total_qubits == 0:
        return 0

    return bits_validos / total_qubits


# ============================================================
# SIMULAÇÃO DE RUÍDO E INTERCEPTAÇÃO
# ============================================================

def simular_ruido(bits_bob, probabilidade_erro):
    """
    Simula ruído no canal quântico.

    Para cada bit recebido por Bob, existe uma probabilidade de erro.
    Quando o erro ocorre, o bit é invertido.
    """
    bits_com_ruido = bits_bob.copy()

    for i in range(len(bits_com_ruido)):
        if random.random() < probabilidade_erro:
            bits_com_ruido[i] = 1 - bits_com_ruido[i]

    return bits_com_ruido


def simular_interceptacao(bits_alice, bases_alice):
    """
    Simula a presença de uma interceptadora, chamada Eva.

    Eva tenta medir os qubits enviados por Alice usando bases aleatórias.
    Quando Eva escolhe a base correta, ela obtém o bit correto.
    Quando escolhe a base errada, o resultado se torna aleatório.

    Depois disso, Eva retransmite os bits medidos para Bob.
    """
    n = len(bits_alice)

    bases_eva = gerar_bases(n)
    bits_eva = []

    for i in range(n):
        if bases_eva[i] == bases_alice[i]:
            bits_eva.append(bits_alice[i])
        else:
            bits_eva.append(random.randint(0, 1))

    return bits_eva, bases_eva


# ============================================================
# EXECUÇÃO PRINCIPAL DO BB84
# ============================================================

def executar_bb84(n_qubits=128, nivel_ruido=0.0, com_eva=False):
    """
    Executa uma simulação completa do protocolo BB84.

    Etapas:
    1. Alice gera bits aleatórios.
    2. Alice escolhe bases aleatórias.
    3. Bob escolhe bases aleatórias.
    4. Os qubits são codificados.
    5. Bob realiza a medição.
    6. As bases são comparadas.
    7. A chave bruta é formada.
    8. A QBER é calculada.
    """
    inicio = time.perf_counter()

    # Alice gera sua sequência de bits e bases
    bits_alice = gerar_bits_aleatorios(n_qubits)
    bases_alice = gerar_bases(n_qubits)

    # Bob escolhe suas bases de medição
    bases_bob = gerar_bases(n_qubits)

    # Caso exista interceptação, Eva mede e retransmite os qubits
    if com_eva:
        bits_envio, bases_envio = simular_interceptacao(
            bits_alice,
            bases_alice
        )
    else:
        bits_envio = bits_alice
        bases_envio = bases_alice

    # Codificação dos qubits
    circuito = codificar_qubits(bits_envio, bases_envio)

    # Medição feita por Bob
    circuito = medir_qubits(circuito, bases_bob)

    # Execução no simulador quântico
    simulador = AerSimulator()
    resultado = simulador.run(circuito, shots=1).result()
    contagens = resultado.get_counts()

    # O Qiskit retorna os bits em ordem invertida
    medicao = list(contagens.keys())[0]
    bits_bob = [int(bit) for bit in reversed(medicao)]

    # Aplicação de ruído simples, caso configurado
    if nivel_ruido > 0:
        bits_bob = simular_ruido(bits_bob, nivel_ruido)

    # Comparação das bases de Alice e Bob
    indices_validos = comparar_bases(bases_alice, bases_bob)

    chave_alice = []
    chave_bob = []

    for i in indices_validos:
        chave_alice.append(bits_alice[i])
        chave_bob.append(bits_bob[i])

    # Cálculo das métricas
    qber = calcular_qber(chave_alice, chave_bob)
    taxa_geracao = calcular_taxa(n_qubits, len(chave_alice))

    fim = time.perf_counter()
    tempo_execucao = fim - inicio

    resultado_final = {
        "qubits_transmitidos": n_qubits,
        "bits_validos": len(chave_alice),
        "taxa_geracao": taxa_geracao,
        "qber": qber,
        "chave_segura": qber <= 0.11,
        "com_eva": com_eva,
        "nivel_ruido": nivel_ruido,
        "tempo_execucao": tempo_execucao,
        "chave_alice": chave_alice,
        "chave_bob": chave_bob
    }

    return resultado_final


def exibir_resultado(resultado):
    """
    Exibe no terminal os principais dados de uma execução do protocolo BB84.
    """
    print("\nResultado da simulação BB84")
    print("-" * 45)
    print(f"Qubits transmitidos: {resultado['qubits_transmitidos']}")
    print(f"Bits válidos: {resultado['bits_validos']}")
    print(f"Taxa de geração da chave: {resultado['taxa_geracao'] * 100:.2f}%")
    print(f"QBER: {resultado['qber'] * 100:.2f}%")
    print(f"Ruído aplicado: {resultado['nivel_ruido'] * 100:.2f}%")
    print(f"Interceptação por Eva: {'Sim' if resultado['com_eva'] else 'Não'}")
    print(f"Chave considerada segura: {'Sim' if resultado['chave_segura'] else 'Não'}")
    print(f"Tempo de execução: {resultado['tempo_execucao']:.6f} segundos")


# ============================================================
# COLETA DE MÉTRICAS
# ============================================================

def executar_repeticoes(n_qubits=128, nivel_ruido=0.0, com_eva=False, repeticoes=30):
    """
    Executa o protocolo BB84 várias vezes para obter médias mais estáveis.
    """
    resultados = []

    for _ in range(repeticoes):
        resultado = executar_bb84(
            n_qubits=n_qubits,
            nivel_ruido=nivel_ruido,
            com_eva=com_eva
        )
        resultados.append(resultado)

    return resultados


def calcular_media(resultados, campo):
    """
    Calcula a média de um determinado campo dos resultados.
    """
    valores = []

    for resultado in resultados:
        valores.append(resultado[campo])

    if len(valores) == 0:
        return 0

    return sum(valores) / len(valores)


def coletar_metricas(repeticoes=30):
    """
    Coleta métricas para três cenários principais:
    1. Canal ideal
    2. Canal com ruído
    3. Canal com interceptação
    """
    cenarios = {
        "Ideal": {
            "nivel_ruido": 0.0,
            "com_eva": False
        },
        "Com ruído": {
            "nivel_ruido": 0.05,
            "com_eva": False
        },
        "Com Eva": {
            "nivel_ruido": 0.0,
            "com_eva": True
        }
    }

    metricas = {}

    for nome_cenario, configuracao in cenarios.items():
        resultados = executar_repeticoes(
            n_qubits=128,
            nivel_ruido=configuracao["nivel_ruido"],
            com_eva=configuracao["com_eva"],
            repeticoes=repeticoes
        )

        metricas[nome_cenario] = {
            "qber_media": calcular_media(resultados, "qber"),
            "taxa_geracao_media": calcular_media(resultados, "taxa_geracao"),
            "bits_validos_media": calcular_media(resultados, "bits_validos"),
            "tempo_medio": calcular_media(resultados, "tempo_execucao")
        }

    return metricas


def coletar_metricas_por_ruido(repeticoes=30):
    """
    Executa o BB84 com diferentes níveis de ruído para observar
    o impacto na QBER.
    """
    niveis_ruido = [0.0, 0.01, 0.03, 0.05, 0.08, 0.10, 0.12, 0.15]
    qber_por_ruido = []

    for ruido in niveis_ruido:
        resultados = executar_repeticoes(
            n_qubits=128,
            nivel_ruido=ruido,
            com_eva=False,
            repeticoes=repeticoes
        )

        qber_media = calcular_media(resultados, "qber")
        qber_por_ruido.append(qber_media)

    return niveis_ruido, qber_por_ruido


# ============================================================
# GERAÇÃO DE GRÁFICOS
# ============================================================

def gerar_grafico_qber_cenarios(metricas, pasta_saida):
    """
    Gera gráfico da QBER média por cenário.
    """
    cenarios = list(metricas.keys())
    qbers = []

    for cenario in cenarios:
        qbers.append(metricas[cenario]["qber_media"] * 100)

    plt.figure(figsize=(8, 5))
    plt.bar(cenarios, qbers)
    plt.axhline(y=11, linestyle="--", label="Limiar BB84 (11%)")
    plt.title("QBER média por cenário")
    plt.xlabel("Cenário")
    plt.ylabel("QBER (%)")
    plt.legend()
    plt.tight_layout()
    plt.savefig(os.path.join(pasta_saida, "qber_por_cenario.png"))
    plt.close()


def gerar_grafico_taxa_chave(metricas, pasta_saida):
    """
    Gera gráfico da taxa média de geração da chave por cenário.
    """
    cenarios = list(metricas.keys())
    taxas = []

    for cenario in cenarios:
        taxas.append(metricas[cenario]["taxa_geracao_media"] * 100)

    plt.figure(figsize=(8, 5))
    plt.bar(cenarios, taxas)
    plt.title("Taxa média de geração da chave")
    plt.xlabel("Cenário")
    plt.ylabel("Taxa de geração (%)")
    plt.tight_layout()
    plt.savefig(os.path.join(pasta_saida, "taxa_geracao_chave.png"))
    plt.close()


def gerar_grafico_qber_ruido(niveis_ruido, qber_por_ruido, pasta_saida):
    """
    Gera gráfico mostrando o impacto do ruído na QBER.
    """
    niveis_percentual = []
    qber_percentual = []

    for ruido in niveis_ruido:
        niveis_percentual.append(ruido * 100)

    for qber in qber_por_ruido:
        qber_percentual.append(qber * 100)

    plt.figure(figsize=(8, 5))
    plt.plot(niveis_percentual, qber_percentual, marker="o")
    plt.axhline(y=11, linestyle="--", label="Limiar BB84 (11%)")
    plt.title("Impacto do ruído na QBER")
    plt.xlabel("Nível de ruído (%)")
    plt.ylabel("QBER média (%)")
    plt.legend()
    plt.tight_layout()
    plt.savefig(os.path.join(pasta_saida, "qber_por_ruido.png"))
    plt.close()


def gerar_todos_os_graficos(metricas, niveis_ruido, qber_por_ruido, pasta_saida="resultados_bb84"):
    """
    Cria a pasta de saída e gera todos os gráficos da simulação.
    """
    os.makedirs(pasta_saida, exist_ok=True)

    gerar_grafico_qber_cenarios(metricas, pasta_saida)
    gerar_grafico_taxa_chave(metricas, pasta_saida)
    gerar_grafico_qber_ruido(niveis_ruido, qber_por_ruido, pasta_saida)

    print(f"\nGráficos salvos na pasta: {pasta_saida}")


# ============================================================
# EXECUÇÃO DO PROGRAMA
# ============================================================

if __name__ == "__main__":
    pasta_saida = "resultados_bb84"

    print("\nTCC — Proteção de Dados com Criptografia Quântica")
    print("Modelo 2 — Criptografia Quântica Simulada com BB84")
    print("=" * 60)

    print("\nCenário 1: Canal ideal")
    resultado_ideal = executar_bb84(
        n_qubits=128,
        nivel_ruido=0.0,
        com_eva=False
    )
    exibir_resultado(resultado_ideal)

    print("\nCenário 2: Canal com ruído")
    resultado_ruido = executar_bb84(
        n_qubits=128,
        nivel_ruido=0.05,
        com_eva=False
    )
    exibir_resultado(resultado_ruido)

    print("\nCenário 3: Canal com interceptação")
    resultado_eva = executar_bb84(
        n_qubits=128,
        nivel_ruido=0.0,
        com_eva=True
    )
    exibir_resultado(resultado_eva)

    print("\nColetando métricas para geração dos gráficos...")
    metricas = coletar_metricas(repeticoes=30)

    niveis_ruido, qber_por_ruido = coletar_metricas_por_ruido(
        repeticoes=30
    )

    gerar_todos_os_graficos(
        metricas=metricas,
        niveis_ruido=niveis_ruido,
        qber_por_ruido=qber_por_ruido,
        pasta_saida=pasta_saida
    )

    print("\nExecução concluída.")